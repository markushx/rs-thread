/* The last 24 KiB of flash (six 4 KiB pages) hold the persistent settings and
   are not part of the program image: the linker cannot place code there, and
   probe-rs only erases the pages of the image when it flashes, so the settings
   survive a reflash. The layout (see the `nrf52840_leader::flash` module):
     0x000FA000  Thread settings, two banks of one page
     0x000FC000  key-value store of the Matter light, two banks of two pages */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 1000K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}

__nvm_start = ORIGIN(FLASH) + LENGTH(FLASH);
