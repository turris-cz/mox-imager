# `mox-imager` - a tool for manipulating / uploading Marvell's Armada 3720 firmware

Features over Marvell's original `WtpDownloader`:
* can upload firmware over UART faster (with baudrates up to 6 MBaud)
* can upload `flash-image.bin` over UART (the code changes the SPI bootflashsign to UART)
* mini-terminal (implementation from U-Boot's `kwboot`)

Other features:
* create ECDSA signed images (Turris MOX boards are locked to only boot signed firmware)
* burning board information to OTP (MAC address, serial number, signing key) - currently implemented for Turris MOX

## Usage

### Upload firmware over UART

Can upload images as `WtpDownloader`
```
mox-imager -D /dev/ttyUSB0 .../uart-images/{TIM_ATF.bin,wtmi_h.bin,boot-image_h.bin}
```

But can also upload `flash-image.bin` over UART
```
mox-imager -D /dev/ttyUSB0 .../flash-image.bin
```

### Upload with higher baudrate (`-b BAUDRATE` flag)

```
mox-imager -D /dev/ttyUSB0 -b 3000000 .../flash-image.bin
```

### Upload and start mini-terminal after uploading (`-t` flag)

```
mox-imager -D /dev/ttyUSB0 -t .../flash-image.bin
```

### Send escape sequence before uploading (to force boot from UART)

Sometimes needs several tries
```
mox-imager -D /dev/ttyUSB0 -E .../flash-image.bin
```

### Print image info

```
mox-imager .../flash-image.bin
```

### Also disassemble GPP packages

```
mox-imager -S .../flash-image.bin
```
