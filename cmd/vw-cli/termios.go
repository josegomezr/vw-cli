package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

type Termios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [19]uint8
	Ispeed uint32
	Ospeed uint32
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) {
	const SYS_IOCTL = 16
	_, _, e1 := syscall.Syscall(SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if e1 != 0 {
		err = fmt.Errorf("syscall error: %d", e1)
	}
	return
}

func tcgetattr(fd uintptr, argp *Termios) error {
	const TCGETS = 0x5401
	return ioctlPtr(int(fd), TCGETS, unsafe.Pointer(argp))
}

func tcsetattr(fd, action uintptr, argp *Termios) error {
	const TCSETS = 0x5402
	return ioctlPtr(int(fd), TCSETS, unsafe.Pointer(argp))
}

func disableecho() {
	const ECHO = 0x8
	termios := Termios{}
	if err := tcgetattr(os.Stdin.Fd(), &termios); err != nil {
		fmt.Println("error:", err)
		return
	}
	termios.Lflag &= ^uint32(ECHO)
	if err := tcsetattr(os.Stdin.Fd(), 0, &termios); err != nil {
		fmt.Println("error:", err)
		return
	}
}

func enableecho() {
	const ECHO = 0x8
	termios := Termios{}
	if err := tcgetattr(os.Stdin.Fd(), &termios); err != nil {
		fmt.Println("error:", err)
		return
	}
	termios.Lflag |= uint32(ECHO)
	if err := tcsetattr(os.Stdin.Fd(), 0, &termios); err != nil {
		fmt.Println("error:", err)
		return
	}
}

func askPass(prompt string) string {
	if prompt != "" {
		fmt.Print(prompt)
	}
	var text string
	disableecho()
	defer enableecho()
	reader := bufio.NewReader(os.Stdin)
	text, _ = reader.ReadString('\n')
	text = strings.TrimSpace(text)
	fmt.Println()
	return text
}
