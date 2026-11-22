package reach

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// The panel has no server-side language setting, so alert mail carries both languages.
var verdictText = map[Verdict][2]string{
	OK: {
		"已恢复，中国大陆可以正常连接。",
		"is reachable from mainland China again.",
	},
	PortBlocked: {
		"端口可能被墙：中国大陆连不上这个端口，其他地区正常。可以先给这条线路换一个端口；如果换了之后很快又连不上，多半是 IP 被墙了。",
		"port looks blocked: mainland China cannot reach this port while other regions can. Try moving the line to another port; if the new port stops working soon after, the IP itself is probably blocked.",
	},
	IPBlocked: {
		"IP 可能被墙：中国大陆完全连不上这台服务器，其他地区正常。换端口没有用，需要更换服务器 IP。",
		"IP looks blocked: mainland China cannot reach this server at all while other regions can. A new port will not help; the server needs a new IP address.",
	},
	Down: {
		"线路不通：其他地区也连不上，多半不是被墙，而是服务器或 Xray 没在运行。请登录面板或服务器检查。",
		"is down: other regions cannot reach it either, so this is probably not a block. Check that the server and Xray are running.",
	},
}

func (c Change) address() string {
	if c.Port == 0 {
		return c.Host
	}
	return net.JoinHostPort(strings.Trim(c.Host, "[]"), strconv.Itoa(c.Port))
}

// AlertMail writes one message covering every change of a round.
func AlertMail(changes []Change) (subject, body string) {
	subject = "Mintyx：线路已恢复 / lines reachable again"
	for _, c := range changes {
		if c.To.Bad() {
			subject = "Mintyx：有线路从中国大陆连不上了 / lines unreachable from mainland China"
			break
		}
	}
	var zh, en strings.Builder
	for _, c := range changes {
		text := verdictText[c.To]
		fmt.Fprintf(&zh, "- %s（%s）%s\n", c.Name, c.address(), text[0])
		fmt.Fprintf(&en, "- %s (%s) %s\n", c.Name, c.address(), text[1])
	}
	body = zh.String() + "\n" + en.String() + "\n" +
		"这封邮件由你自己的 Mintyx 面板通过你填写的 SMTP 服务器发出。\n" +
		"Sent by your own Mintyx panel through the SMTP server you configured.\n"
	return subject, body
}
