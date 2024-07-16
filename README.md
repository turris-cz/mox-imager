# `mox-imager` - a tool for manipulating / uploading Marvell's Armada 3720 firmware

Features over Marvell's original `WtpDownloader`:
* can upload firmware over UART faster (with baudrates up to 6 MBaud)
* can upload `flash-image.bin` over UART (the code changes the SPI bootflashsign to UART)
* can upload firmware over UART in separate images without headers (filename arguments must be supplied in correct order)
* mini-terminal (implementation from U-Boot's `kwboot`)

Other features:
* create ECDSA signed images (Turris MOX boards are locked to only boot signed firmware)
* burning board information to OTP (MAC address, serial number, signing key) - currently implemented for Turris MOX
* read eFuse OTP memory

## Usage

### Upload firmware over UART

Can upload unsigned images as `WtpDownloader`
```
mox-imager -D /dev/ttyUSB0 .../uart-images/{TIM_ATF.bin,wtmi_h.bin,boot-image_h.bin}
```

Can upload signed images as `WtpDownloader`
```
mox-imager -D /dev/ttyUSB0 -E .../uart-images/{TIM_ATF_TRUSTED.bin,TIMN_ATF_TRUSTED.bin,wtmi_h.bin,boot-image_h.bin}
```

But can also upload unsigned `flash-image.bin` over UART
```
mox-imager -D /dev/ttyUSB0 .../flash-image.bin
```

And can also upload signed firmware in separate images
```
mox-imager -D /dev/ttyUSB0 .../trusted-secure-firmware-uart.bin .../a53-firmware.bin
```

### Send escape sequence before uploading (to force boot from UART)

```
mox-imager -D /dev/ttyUSB0 -E .../flash-image.bin
```

### Upload with higher baudrate (`-b BAUDRATE` flag)

```
mox-imager -D /dev/ttyUSB0 -b 3000000 .../flash-image.bin
```

### Upload and start mini-terminal after uploading (`-t` flag)

```
mox-imager -D /dev/ttyUSB0 -t .../flash-image.bin
```

### Upload with maximal baudrate 6000000 and start mini-terminal

```
mox-imager -D /dev/ttyUSB0 -b 6000000 -t .../flash-image.bin
```

### Only start mini-terminal (like minicom/kermit) without uploading

```
mox-imager -D /dev/ttyUSB0 -t
```

### Read device eFuse OTP memory

```
mox-imager -D /dev/ttyUSB0 -E -Rauto
```

### Print image info

```
mox-imager .../flash-image.bin
```

### Also disassemble GPP packages

```
mox-imager -S .../flash-image.bin
```
