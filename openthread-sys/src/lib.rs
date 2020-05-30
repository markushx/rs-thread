#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

//pub use bindings::*;

//mod test_platform;
//::plat_settings;

#[cfg(test)]
mod tests {
    use super::*;
 
    #[test]
    fn init_openthread() {
        unsafe {
            let instance = otInstanceInitSingle();
            let initted = otInstanceIsInitialized(instance);

            match initted {
                r if r == (true as _) => panic!("Instance should not be initialised already"),
                r if r == (false as _) => {},
                r => panic!("Unknown return value = {}", r),
            }
        }
    }
}
