import http.server
import socketserver
import os
import socket
import urllib.parse
import json
import logging
import traceback

PORT = 8080
NOTES_FILE = "notas_recibidas.txt"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alpine Cloud Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-color: #0f172a;
            --glass-bg: rgba(30, 41, 59, 0.7);
            --glass-border: rgba(255, 255, 255, 0.1);
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --danger: #ef4444;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }

        body {
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, hsla(253,16%,7%,1) 0, transparent 50%), 
                radial-gradient(at 50% 0%, hsla(225,39%,30%,0.5) 0, transparent 50%), 
                radial-gradient(at 100% 0%, hsla(339,49%,30%,0.5) 0, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 2rem 1rem;
        }

        .container { width: 100%; max-width: 800px; }
        
        .header { text-align: center; margin-bottom: 2rem; animation: fadeInDown 0.8s ease; }
        .header h1 { font-weight: 600; letter-spacing: -0.5px; font-size: 2.5rem; background: linear-gradient(to right, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .header p { color: var(--text-muted); margin-top: 0.5rem; }

        .glass-panel {
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            animation: fadeInUp 0.8s ease;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .glass-panel:hover { transform: translateY(-2px); box-shadow: 0 15px 30px -5px rgba(0, 0, 0, 0.4); }

        h2 { font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
        h2 i { color: var(--primary); }

        /* Notes Section */
        textarea {
            width: 100%; height: 120px; background: rgba(0,0,0,0.2); border: 1px solid var(--glass-border);
            border-radius: 8px; padding: 1rem; color: white; resize: vertical; margin-bottom: 1rem;
            transition: border-color 0.3s ease;
        }
        textarea:focus { outline: none; border-color: var(--primary); }

        .btn {
            background: var(--primary); color: white; border: none; padding: 0.75rem 1.5rem;
            border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.3s ease;
            display: inline-flex; align-items: center; gap: 0.5rem; justify-content: center;
        }
        .btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
        .btn:active { transform: translateY(1px); }

        /* Upload Section */
        .drop-zone {
            border: 2px dashed var(--glass-border); border-radius: 12px; padding: 3rem 2rem;
            text-align: center; cursor: pointer; transition: all 0.3s ease; background: rgba(0,0,0,0.1);
        }
        .drop-zone.dragover { border-color: var(--primary); background: rgba(59, 130, 246, 0.1); }
        .drop-zone i { font-size: 3rem; color: var(--primary); margin-bottom: 1rem; }
        .drop-zone p { color: var(--text-muted); }
        #fileInput { display: none; }

        /* Progress Bar */
        .progress-container { display: none; margin-top: 1rem; }
        .progress-bar { width: 100%; height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; }
        .progress-fill { width: 0%; height: 100%; background: var(--primary); transition: width 0.3s ease; }
        .progress-text { font-size: 0.875rem; color: var(--text-muted); margin-top: 0.5rem; text-align: right; }

        /* File List */
        .search-bar { width: 100%; padding: 0.75rem 1rem; background: rgba(0,0,0,0.2); border: 1px solid var(--glass-border); border-radius: 8px; color: white; margin-bottom: 1rem; }
        .search-bar:focus { outline: none; border-color: var(--primary); }
        
        .file-list { list-style: none; max-height: 400px; overflow-y: auto; padding-right: 0.5rem; }
        .file-list::-webkit-scrollbar { width: 6px; }
        .file-list::-webkit-scrollbar-thumb { background: var(--glass-border); border-radius: 4px; }

        .file-item {
            display: flex; align-items: center; justify-content: space-between;
            padding: 0.75rem; border-bottom: 1px solid var(--glass-border); transition: background 0.2s ease;
        }
        .file-item:last-child { border-bottom: none; }
        .file-item:hover { background: rgba(255,255,255,0.05); }
        
        .file-info { display: flex; align-items: center; gap: 1rem; flex: 1; overflow: hidden; text-decoration: none; color: inherit; }
        .file-icon { font-size: 1.5rem; color: var(--text-muted); width: 24px; text-align: center; }
        .file-name { font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .file-meta { font-size: 0.8rem; color: var(--text-muted); }
        
        .file-actions { display: flex; gap: 0.5rem; }
        .action-btn { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 0.5rem; border-radius: 4px; transition: all 0.2s; }
        .action-btn:hover { background: rgba(255,255,255,0.1); color: white; }
        .action-btn.delete:hover { background: rgba(239, 68, 68, 0.2); color: var(--danger); }

        /* Toast Notifications */
        #toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 1000; }
        .toast {
            background: var(--glass-bg); backdrop-filter: blur(10px); border: 1px solid var(--glass-border);
            color: white; padding: 1rem 1.5rem; border-radius: 8px; margin-top: 0.5rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2); display: flex; align-items: center; gap: 0.75rem;
            animation: slideInRight 0.3s ease forwards;
        }
        .toast.success i { color: #10b981; }
        .toast.error i { color: var(--danger); }
        .toast.hiding { animation: slideOutRight 0.3s ease forwards; }

        @keyframes fadeInDown { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes slideInRight { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes slideOutRight { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }

        @media (max-width: 600px) {
            .file-meta { display: none; }
            .header h1 { font-size: 2rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Alpine Cloud</h1>
            <p>Comparte archivos y notas rápidamente</p>
        </div>

        <div class="glass-panel">
            <h2><i class="fa-regular fa-clipboard"></i> Notas y Texto</h2>
            <textarea id="noteText" placeholder="Escribe tu nota aquí... (Se guardará en notas_recibidas.txt)"></textarea>
            <button class="btn" onclick="saveNote()" style="width: 100%;">
                <i class="fa-solid fa-save"></i> Guardar Nota
            </button>
        </div>

        <div class="glass-panel">
            <h2><i class="fa-solid fa-cloud-arrow-up"></i> Subir Archivos</h2>
            <div class="drop-zone" id="dropZone" onclick="document.getElementById('fileInput').click()">
                <i class="fa-solid fa-file-arrow-up"></i>
                <p>Arrastra archivos aquí o haz clic para seleccionar</p>
                <input type="file" id="fileInput" multiple onchange="handleFiles(this.files)">
            </div>
            
            <div class="progress-container" id="progressContainer">
                <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
                <div class="progress-text" id="progressText">0%</div>
            </div>
        </div>

        <div class="glass-panel">
            <h2><i class="fa-regular fa-folder-open"></i> Explorador de Archivos</h2>
            <input type="text" class="search-bar" id="searchInput" placeholder="Buscar archivos..." oninput="filterFiles()">
            <ul class="file-list" id="fileList">
                <li style="text-align:center; color:var(--text-muted); padding: 1rem;">Cargando archivos...</li>
            </ul>
        </div>
    </div>

    <div id="toast-container"></div>

    <script>
        // File Icons mapping
        const iconMap = {
            'pdf': 'fa-file-pdf', 'doc': 'fa-file-word', 'docx': 'fa-file-word',
            'xls': 'fa-file-excel', 'xlsx': 'fa-file-excel', 'jpg': 'fa-file-image',
            'jpeg': 'fa-file-image', 'png': 'fa-file-image', 'gif': 'fa-file-image',
            'mp4': 'fa-file-video', 'mp3': 'fa-file-audio', 'zip': 'fa-file-zipper',
            'rar': 'fa-file-zipper', 'txt': 'fa-file-lines', 'py': 'fa-file-code',
            'html': 'fa-file-code', 'js': 'fa-file-code', 'css': 'fa-file-code'
        };

        function getFileIcon(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            return iconMap[ext] || 'fa-file';
        }

        // Notifications
        function showToast(message, type = 'success') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            const icon = type === 'success' ? 'fa-circle-check' : 'fa-circle-exclamation';
            toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
            
            container.appendChild(toast);
            
            setTimeout(() => {
                toast.classList.add('hiding');
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }

        // Fetch and display files
        async function loadFiles() {
            try {
                const res = await fetch('/api/files');
                const data = await res.json();
                const list = document.getElementById('fileList');
                list.innerHTML = '';
                
                if (data.files.length === 0) {
                    list.innerHTML = '<li style="text-align:center; color:var(--text-muted); padding: 1rem;">No hay archivos en el directorio</li>';
                    return;
                }

                data.files.forEach(file => {
                    const li = document.createElement('li');
                    li.className = 'file-item';
                    li.innerHTML = `
                        <a href="/${encodeURIComponent(file.name)}" class="file-info" target="_blank">
                            <i class="fa-solid ${getFileIcon(file.name)} file-icon"></i>
                            <div>
                                <div class="file-name" title="${file.name}">${file.name}</div>
                                <div class="file-meta">${file.size}</div>
                            </div>
                        </a>
                        <div class="file-actions">
                            <a href="/${encodeURIComponent(file.name)}" download class="action-btn" title="Descargar">
                                <i class="fa-solid fa-download"></i>
                            </a>
                            <button class="action-btn delete" onclick="deleteFile('${file.name}')" title="Eliminar">
                                <i class="fa-solid fa-trash"></i>
                            </button>
                        </div>
                    `;
                    list.appendChild(li);
                });
            } catch (error) {
                showToast('Error cargando archivos', 'error');
            }
        }

        // Search filter
        function filterFiles() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const items = document.querySelectorAll('.file-item');
            items.forEach(item => {
                const name = item.querySelector('.file-name').textContent.toLowerCase();
                item.style.display = name.includes(query) ? 'flex' : 'none';
            });
        }

        // Delete file
        async function deleteFile(filename) {
            if (!confirm(`¿Estás seguro de que deseas eliminar "${filename}"?`)) return;
            
            try {
                const res = await fetch(`/api/files/${encodeURIComponent(filename)}`, { method: 'DELETE' });
                const data = await res.json();
                if (res.ok) {
                    showToast('Archivo eliminado');
                    loadFiles();
                } else {
                    showToast(data.message || 'Error al eliminar', 'error');
                }
            } catch (error) {
                showToast('Error de conexión', 'error');
            }
        }

        // Save Note
        async function saveNote() {
            const text = document.getElementById('noteText').value;
            if (!text.trim()) {
                showToast('La nota está vacía', 'error');
                return;
            }

            try {
                const res = await fetch('/api/text', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text_content: text })
                });
                
                if (res.ok) {
                    showToast('Nota guardada correctamente');
                    document.getElementById('noteText').value = '';
                } else {
                    showToast('Error al guardar la nota', 'error');
                }
            } catch (error) {
                showToast('Error de conexión', 'error');
            }
        }

        // Drag and Drop Upload
        const dropZone = document.getElementById('dropZone');
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
        });

        dropZone.addEventListener('drop', e => {
            const files = e.dataTransfer.files;
            handleFiles(files);
        }, false);

        function handleFiles(files) {
            if (files.length === 0) return;
            
            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {
                formData.append('file[]', files[i]);
            }

            const xhr = new XMLHttpRequest();
            const progressContainer = document.getElementById('progressContainer');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');

            progressContainer.style.display = 'block';
            progressFill.style.width = '0%';
            progressText.textContent = '0%';

            xhr.upload.addEventListener('progress', e => {
                if (e.lengthComputable) {
                    const percentComplete = Math.round((e.loaded / e.total) * 100);
                    progressFill.style.width = percentComplete + '%';
                    progressText.textContent = percentComplete + '%';
                }
            }, false);

            xhr.addEventListener('load', () => {
                progressContainer.style.display = 'none';
                if (xhr.status >= 200 && xhr.status < 300) {
                    showToast('Archivos subidos correctamente');
                    loadFiles();
                } else {
                    let msg = 'Error al subir';
                    try { msg = JSON.parse(xhr.responseText).message; } catch(e){}
                    showToast(msg, 'error');
                }
                document.getElementById('fileInput').value = '';
            });

            xhr.addEventListener('error', () => {
                progressContainer.style.display = 'none';
                showToast('Error de red al subir', 'error');
            });

            xhr.open('POST', '/api/upload', true);
            xhr.send(formData);
        }

        // Initialize
        loadFiles();
    </script>
</body>
</html>
"""

def get_file_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0

class PortalHandler(http.server.SimpleHTTPRequestHandler):
    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        try:
            if self.path == '/':
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(HTML_CONTENT.encode('utf-8'))
            elif self.path == '/api/files':
                files_data = []
                for f in os.listdir('.'):
                    if os.path.isfile(f) and f != 'sharefiles.py':
                        try:
                            stat = os.stat(f)
                            files_data.append({
                                'name': f,
                                'size': get_file_size(stat.st_size),
                                'raw_size': stat.st_size,
                                'modified': stat.st_mtime
                            })
                        except Exception as e:
                            logging.error(f"Error reading file {f}: {e}")
                
                files_data.sort(key=lambda x: x['modified'], reverse=True)
                self.send_json({'files': files_data})
            else:
                super().do_GET()
        except Exception as e:
            logging.error(f"Error in GET {self.path}: {e}")
            self.send_error(500, "Internal Server Error")

    def do_DELETE(self):
        try:
            if self.path.startswith('/api/files/'):
                filename = urllib.parse.unquote(self.path.split('/')[-1])
                filename = os.path.basename(filename) # Security measure
                if os.path.exists(filename) and os.path.isfile(filename):
                    os.remove(filename)
                    self.send_json({'status': 'success', 'message': f'File {filename} deleted'})
                else:
                    self.send_json({'status': 'error', 'message': 'File not found'}, status=404)
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logging.error(f"Error in DELETE {self.path}: {e}")
            self.send_json({'status': 'error', 'message': str(e)}, status=500)

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length == 0:
                self.send_json({'status': 'error', 'message': 'No content'}, status=400)
                return

            if self.path == '/api/text':
                data = self.rfile.read(length).decode('utf-8')
                try:
                    json_data = json.loads(data)
                    text = json_data.get('text_content', '')
                except:
                    parsed = urllib.parse.parse_qs(data)
                    text = parsed.get('text_content', [''])[0]
                
                if text:
                    with open(NOTES_FILE, "a", encoding="utf-8") as f:
                        f.write(text + "\n---\n")
                    self.send_json({'status': 'success', 'message': 'Note saved successfully'})
                else:
                    self.send_json({'status': 'error', 'message': 'Empty note'}, status=400)

            elif self.path == '/api/upload':
                content_type = self.headers.get('Content-Type', '')
                if 'boundary=' not in content_type:
                    self.send_json({'status': 'error', 'message': 'Invalid Content-Type'}, status=400)
                    return
                
                boundary = content_type.split('boundary=')[1].encode()
                body = self.rfile.read(length)
                parts = body.split(b'--' + boundary)
                uploaded_files = []
                
                for p in parts:
                    if b'filename="' in p:
                        try:
                            header_content_split = p.split(b'\r\n\r\n', 1)
                            if len(header_content_split) < 2:
                                continue
                            h, c = header_content_split
                            
                            h_str = h.decode('utf-8', 'ignore')
                            fn_start = h_str.find('filename="') + 10
                            fn_end = h_str.find('"', fn_start)
                            filename = h_str[fn_start:fn_end]
                            filename = os.path.basename(filename) # Prevent directory traversal
                            
                            if filename:
                                content = c
                                if content.endswith(b'\r\n'):
                                    content = content[:-2]
                                
                                with open(filename, 'wb') as f:
                                    f.write(content)
                                uploaded_files.append(filename)
                        except Exception as e:
                            logging.error(f"Error parsing part: {e}")
                
                if uploaded_files:
                    self.send_json({'status': 'success', 'message': f'Uploaded {len(uploaded_files)} file(s)', 'files': uploaded_files})
                else:
                    self.send_json({'status': 'error', 'message': 'No files uploaded'}, status=400)
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logging.error(f"Error in POST {self.path}: {traceback.format_exc()}")
            self.send_json({'status': 'error', 'message': str(e)}, status=500)

def main():
    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", PORT), PortalHandler) as httpd:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            except:
                ip = "127.0.0.1"
            finally:
                s.close()
            
            print(f"=================================================")
            print(f"🚀 Alpine Cloud Portal is running!")
            print(f"👉 Open this link in your browser:")
            print(f"🌐 http://{ip}:{PORT}")
            print(f"=================================================")
            logging.info("Server started successfully. Press Ctrl+C to stop.")
            httpd.serve_forever()
    except OSError as e:
        if e.errno == 98 or "Address already in use" in str(e):
            logging.error(f"Port {PORT} is already in use. Please stop the other process or change the port.")
        else:
            logging.error(f"Failed to start server: {e}")
    except KeyboardInterrupt:
        logging.info("Server stopped manually.")

if __name__ == "__main__":
    main()