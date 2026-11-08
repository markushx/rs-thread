//! Dispatch classification and mesh forwarding tests.

use opentrust_core::Error;

use crate::forward::{
    Dispatch, DropReason, LowpanFrame, MeshOutcome, classify, handle_mesh, parse_frame,
    parse_inner, rewrite,
};
use crate::mesh::{MESH_HEADER_HOPS_LEFT, MeshHeader};

const IPHC: [u8; 6] = [0x7a, 0x33, 0x3a, 0x80, 0x00, 0x01];

#[test]
fn classify_payloads() {
    assert_eq!(classify(&[]), Dispatch::Empty);
    assert_eq!(classify(&[0xb1, 1, 0, 2, 0]), Dispatch::Mesh);
    // Too short for a mesh header: not classified as mesh (falls through).
    assert_eq!(classify(&[0xb1, 1, 0, 2]), Dispatch::Unsupported);
    assert_eq!(classify(&[0xc7, 0xef, 0x12, 0x34]), Dispatch::Fragment);
    assert_eq!(
        classify(&[0xe7, 0xef, 0x12, 0x34, 0x64]),
        Dispatch::Fragment
    );
    assert_eq!(classify(&IPHC), Dispatch::Iphc);
    assert_eq!(classify(&[0x40, 1, 2]), Dispatch::Unsupported); // uncompressed IPv6
    assert_eq!(classify(&[0x01, 1, 2]), Dispatch::Unsupported); // LOWPAN_BC0 / NALP
    assert_eq!(classify(&[0x41]), Dispatch::Unsupported);
}

#[test]
fn parse_frames() {
    assert_eq!(parse_frame(&[]), Ok(LowpanFrame::Empty));
    assert_eq!(parse_frame(&IPHC), Ok(LowpanFrame::Iphc(&IPHC)));
    assert_eq!(parse_frame(&[0x40, 1]), Err(Error::Parse));
    let m = [0xb1, 0x01, 0x00, 0x02, 0x00, 0x7a, 0x33];
    let LowpanFrame::Mesh { header, payload } = parse_frame(&m).unwrap() else {
        panic!("not mesh")
    };
    assert_eq!(header, MeshHeader::new(0x100, 0x200, 1));
    assert_eq!(payload, &[0x7a, 0x33]);
    let f = [0xc7, 0xef, 0x12, 0x34, 0x7a];
    let LowpanFrame::Fragment { header, payload } = parse_frame(&f).unwrap() else {
        panic!("not frag")
    };
    assert_eq!(header.datagram_size, 0x7ef);
    assert_eq!(payload, &[0x7a]);
    // Mesh inner must be fragment or IPHC.
    assert!(parse_inner(&IPHC).is_ok());
    assert!(parse_inner(&f).is_ok());
    assert_eq!(parse_inner(&m), Err(Error::Parse));
    assert_eq!(parse_inner(&[]), Err(Error::Parse));
}

fn mesh_frame(src: u16, dst: u16, hops: u8, inner: &[u8]) -> std::vec::Vec<u8> {
    let mut b = [0u8; 127];
    let n = rewrite(&MeshHeader::new(src, dst, hops), inner, &mut b).unwrap();
    b[..n].to_vec()
}

#[test]
fn deliver_forward_drop() {
    let me = 0x0800u16;
    let routes = |d: u16| match d {
        0x0c00 => Some(0x0c00),
        0x1000 => Some(0x0c00),
        0x1400 => Some(0x0400),
        _ => None,
    };

    // For me (own RLOC16) -> deliver.
    let f = mesh_frame(0x0400, me, 5, &IPHC);
    match handle_mesh(&f, true, &me, &routes, Some(0x0400)) {
        MeshOutcome::Deliver { header, payload } => {
            assert_eq!(header, MeshHeader::new(0x0400, me, 5));
            assert_eq!(payload, &IPHC);
        }
        o => panic!("{o:?}"),
    }
    // For a child of mine -> deliver.
    let local = |r: u16| r == me || r == 0x0803;
    let f = mesh_frame(0x0400, 0x0803, 1, &IPHC);
    assert!(matches!(
        handle_mesh(&f, true, &local, &routes, None),
        MeshOutcome::Deliver { .. }
    ));
    // Delivery with hops 0 still works; garbage inner is dropped.
    let f = mesh_frame(0x0400, me, 0, &IPHC);
    assert!(matches!(
        handle_mesh(&f, true, &me, &routes, None),
        MeshOutcome::Deliver { .. }
    ));
    let f = mesh_frame(0x0400, me, 3, &[0x40, 1, 2]);
    assert_eq!(
        handle_mesh(&f, true, &me, &routes, None),
        MeshOutcome::Drop(DropReason::Parse)
    );

    // Forward: hops decremented, next hop from the table.
    let f = mesh_frame(0x0400, 0x1000, 3, &IPHC);
    match handle_mesh(&f, true, &me, &routes, Some(0x0400)) {
        MeshOutcome::Forward {
            next_hop,
            header,
            payload,
        } => {
            assert_eq!(next_hop, 0x0c00);
            assert_eq!(header, MeshHeader::new(0x0400, 0x1000, 2));
            let mut out = [0u8; 127];
            let n = rewrite(&header, payload, &mut out).unwrap();
            assert_eq!(&out[..n], &mesh_frame(0x0400, 0x1000, 2, &IPHC)[..]);
        }
        o => panic!("{o:?}"),
    }

    // No hops left, no route, loop, no security, malformed.
    let f = mesh_frame(0x0400, 0x1000, 0, &IPHC);
    assert_eq!(
        handle_mesh(&f, true, &me, &routes, None),
        MeshOutcome::Drop(DropReason::HopsExhausted)
    );
    let f = mesh_frame(0x0400, 0x2000, 3, &IPHC);
    assert_eq!(
        handle_mesh(&f, true, &me, &routes, None),
        MeshOutcome::Drop(DropReason::NoRoute)
    );
    let f = mesh_frame(0x0400, 0x1400, 3, &IPHC);
    assert_eq!(
        handle_mesh(&f, true, &me, &routes, Some(0x0400)),
        MeshOutcome::Drop(DropReason::RoutingLoop)
    );
    assert_eq!(
        handle_mesh(&f, false, &me, &routes, Some(0x0200)),
        MeshOutcome::Drop(DropReason::Security)
    );
    assert_eq!(
        handle_mesh(&f[..4], true, &me, &routes, None),
        MeshOutcome::Drop(DropReason::Parse)
    );
}

#[test]
fn deep_hops_shrink_when_forwarding() {
    let routes = |_d: u16| Some(0x0c00u16);
    let f = mesh_frame(0x0400, 0x1000, 15, &IPHC);
    assert_eq!(f.len(), 6 + IPHC.len());
    let MeshOutcome::Forward {
        header, payload, ..
    } = handle_mesh(&f, true, &0x0800u16, &routes, None)
    else {
        panic!()
    };
    assert_eq!(header.hops_left, 14);
    let mut out = [0u8; 127];
    let n = rewrite(&header, payload, &mut out).unwrap();
    assert_eq!(n, 5 + IPHC.len());
    // Originated frames use OT's initial hops left.
    assert_eq!(MESH_HEADER_HOPS_LEFT, 19);
}
