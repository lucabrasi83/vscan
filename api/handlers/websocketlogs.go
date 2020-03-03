package handlers

import (
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/lucabrasi83/vscan/datadiros"
	"github.com/lucabrasi83/vscan/logging"
)

const (
	// Time allowed to write the file to the client.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the client.
	pongWait = 60 * time.Second

	// Send pings to client with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Poll file for changes with this period.
	filePeriod = 3 * time.Second
)

var (

	// Allowed host Origin
	allowedOrigins = []string{
		"vulscano.vsnl.co.in",
		"vscan.asdlab.net",
		"vscan.tatacommunications.com",
		"vscan.maleeja.com",
		"vscan-back.maleeja.com",
		"vulscano.vsnl.co.in:8443",
		"vscan.vsnl.co.in",
	}

	connWSUpgrade = websocket.Upgrader{
		ReadBufferSize:    8192,
		WriteBufferSize:   8192,
		EnableCompression: true,
		CheckOrigin: func(r *http.Request) bool {
			for _, origin := range allowedOrigins {
				if r.Host == origin {
					return true
				}
			}
			return false
		},
	}
)

func readFileIfModified(lastMod time.Time, filename string) ([]byte, time.Time, error) {

	filenamePath := filepath.FromSlash(datadiros.GetDataDir() + "/" + filename)

	fi, err := abstractInMemoryFS.Stat(filenamePath)

	// Gracefully handle file to stream not existing yet
	if errFileStat, ok := err.(*os.PathError); errFileStat != nil && ok {
		return nil, lastMod, nil
	}
	if err != nil {
		logging.VSCANLog("error", "unable to instantiate in-memory file system: %v", err)
		return nil, lastMod, err
	}
	if !fi.ModTime().After(lastMod) {
		return nil, lastMod, nil
	}

	file, err := abstractInMemoryFS.OpenFile(filenamePath, os.O_RDONLY, 0644)

	if err != nil {
		logging.VSCANLog("error", "unable to open in-memory log file %v with error %v", filename, err)
		return nil, lastMod, err
	}

	defer file.Close()

	p, err := ioutil.ReadAll(file)
	if err != nil {
		logging.VSCANLog("error", "unable to read in-memory log file %v with error %v", filename, err)
		return nil, fi.ModTime(), err
	}
	return p, fi.ModTime(), nil
}

func reader(ws *websocket.Conn) {
	defer ws.Close()
	ws.SetReadLimit(512)
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error { ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}
}

func writer(ws *websocket.Conn, lastMod time.Time, file string) {
	lastError := ""
	pingTicker := time.NewTicker(pingPeriod)
	fileTicker := time.NewTicker(filePeriod)
	defer func() {
		pingTicker.Stop()
		fileTicker.Stop()
		ws.Close()
	}()
	for {
		select {
		case <-fileTicker.C:
			var p []byte
			var err error

			p, lastMod, err = readFileIfModified(lastMod, file)

			if err != nil {
				if s := err.Error(); s != lastError {
					lastError = s
					p = []byte(lastError)
				}
			} else {
				lastError = ""
			}

			if p != nil {
				ws.SetWriteDeadline(time.Now().Add(writeWait))

				if err := ws.WriteMessage(websocket.TextMessage, p); err != nil {
					return
				}
			}
		case <-pingTicker.C:
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				return
			}
		}
	}
}

func ServeWs(c *gin.Context) {

	ws, err := connWSUpgrade.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		if _, ok := err.(websocket.HandshakeError); !ok {
			logging.VSCANLog("error", "Unable to upgrade Websocket connection with error %v", err)
		}
		return
	}
	var lastMod time.Time
	if n, err := strconv.ParseInt(c.Query("lastMod"), 16, 64); err == nil {
		lastMod = time.Unix(0, n)
	}

	var file string
	file = c.Query("logFileRequestHash")
	go writer(ws, lastMod, file)
	reader(ws)
}

//func ServeLogHome(c *gin.Context) {
//	if c.Request.URL.Path != "/api/v1/jobs/all" {
//		c.String(http.StatusNotFound, "Not found")
//		return
//	}
//
//	c.Header("Content-Type", "text/html; charset=utf-8")
//
//	scanJobID := c.Query("scanJobID")
//
//	p, lastMod, err := readFileIfModified(time.Time{}, scanJobID)
//	if err != nil {
//		p = []byte(err.Error())
//		lastMod = time.Unix(0, 0)
//		logging.VSCANLog("error", "Unable to access log file for Websocket stream on job ID %v with error %v",
//			scanJobID, err)
//	}
//	var v = struct {
//		Host      string
//		Data      string
//		LastMod   string
//		ScanJobID string
//	}{
//		c.Request.Host,
//		string(p),
//		strconv.FormatInt(lastMod.UnixNano(), 16),
//		scanJobID,
//	}
//	homeTempl.Execute(c.Writer, &v)
//
//}

//const homeHTML = `<!DOCTYPE html>
//<html lang="en">
//   <head>
//       <title>WebSocket Example</title>
//   </head>
//   <body style="background-color: black;color: white;font-size: 20px;font-family: monospace;padding:10px 50px">
//       <pre id="fileData">{{.Data}}</pre>
//       <script type="text/javascript">
//           (function() {
//               var data = document.getElementById("fileData");
//               var AgentConn = new WebSocket("wss://{{.Host}}/api/v1/jobs/ws?lastMod={{.LastMod}}&scanJobID={{.ScanJobID}}");
//               AgentConn.onclose = function(evt) {
//                   data.textContent = 'Connection closed';
//               }
//               AgentConn.onmessage = function(evt) {
//                   data.textContent = evt.data;
//               }
//           })();
//       </script>
//   </body>
//</html>
//`
