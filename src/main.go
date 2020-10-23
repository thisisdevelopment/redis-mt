package main

import (
	"errors"
	"fmt"
	"github.com/mediocregopher/radix/v3"
	"github.com/tidwall/redcon"
	"io"
	"log"
	"net"
	"strings"
)



type Context struct {
	username string
	prefix string
	conn net.Conn
}
type CommandDef struct {
	keyFirst int
	keyStep int
	keyLast int
}

var addr = ":6379"
var users []string
var commands = map[string]CommandDef{
}

func getUserByRemoteAddr(remoteAddr string) (string, error) {
	dns, err := net.LookupAddr(strings.Split(remoteAddr, ":")[0])
	if err != nil {
		return "", err
	}

	if len(dns) == 0 {
		return "", errors.New("no reverse lookup available for")
	}

	//TODO: configurable
	return strings.Split(dns[0], "_")[1], nil
}

func userExists(username string) bool {
	//TODO: implement
	return false
}

func main() {
	go log.Printf("started server at %s", addr)

	client, clientErr := radix.NewPool("unix", "/tmp/keydb.sock", 1)
	if clientErr != nil {
		log.Fatal(clientErr)
	}

	client.Do(radix.Cmd(nil, "AUTH", "admin", "admin"))
	client.Do(radix.Cmd(&users, "ACL USERS"))

	var cmds []interface{}

	client.Do(radix.Cmd(&cmds, "COMMAND"))
	for k := 0; k<len(cmds); k++ {
		cmd := cmds[k].([]interface{})
		name := string(cmd[0].([]byte))
		cats := cmd[6].([]interface{})
		for j := 0; j < len(cats); j++ {
			if cats[j].(string) == "@dangerous" {
				fmt.Println("Skipped: " + name)
				goto next
			}
		}
		commands[name] = CommandDef{int(cmd[3].(int64)), int(cmd[5].(int64)), int(cmd[4].(int64)) }

	next:
	}

	fmt.Println(commands)

	err := redcon.ListenAndServe(addr,
		func(conn redcon.Conn, cmd redcon.Command) {
			//TODO: determine if valid / special command
			//TODO: determine + rewrite keys

			context := conn.Context().(*Context)

			op := strings.ToLower(string(cmd.Args[0]))
			if op == "quit" {
				conn.WriteString("OK")
				conn.Close()
			} else if val, ok := commands[op]; ok {
				//TODO: resp encoding?
				nextKey := val.keyFirst
				context.conn.Write(cmd.Args[0])
				for i:=1; i<len(cmd.Args); i++ {
					context.conn.Write([]byte(" "))
					if i == nextKey {
						context.conn.Write([]byte(context.prefix))
						nextKey += val.keyStep
						if nextKey > val.keyLast {
							nextKey = 0
						}
					}
					context.conn.Write(cmd.Args[i])
				}
				context.conn.Write([]byte("\r\n"))
			} else {
				context.conn.Write(cmd.Raw)
			}
		},
		func(conn redcon.Conn) bool {

			user, err := getUserByRemoteAddr(conn.RemoteAddr())
			if err != nil {
				log.Printf("rejected: %s", err)
				return false
			}

			log.Printf("accepted: %s", user)

			prefix := user + ":"
			if !userExists(user) {
				log.Printf("create user: %s", user)
				cmdErr := client.Do(radix.Cmd(nil, "ACL", "SETUSER", user, "on", "+@all", "-randomkey", "-@dangerous", "~" + prefix + "*", ">" + user))
				if cmdErr != nil {
					log.Fatal(cmdErr)
				}
			}

			result := make([]byte, 100)
			serverConn, _ := net.Dial("unix", "/tmp/keydb.sock")
			serverConn.Write([]byte("AUTH " + user + " " + user + "\r\n"))
			serverConn.Read(result)

			if string(result[0:3]) != "+OK" {
				log.Printf("Auth failure; received: %s", string(result))
				return false
			}

			context := &Context{
				username: user,
				prefix:   prefix,
				conn:     serverConn,
			}

			go func() {
				io.Copy(conn.NetConn(), serverConn)
			}()

			conn.SetContext(context)

			return true
		},
		func(conn redcon.Conn, err error) {
			// this is called when the connection has been closed
			log.Printf("closed: %s, err: %v", conn.RemoteAddr(), err)

			context := conn.Context().(*Context)
			context.conn.Close()
		},
	)
	if err != nil {
		log.Fatal(err)
	}
}