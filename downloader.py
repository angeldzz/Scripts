import http.server
import socketserver
import socket
import subprocess
import os
import urllib.parse

PORT = 8080
DOWNLOADS_DIR = "downloads"
MEDIA_EXTENSIONS = {'.mp4', '.mkv', '.mp3', '.m4a', '.webm', '.opus'}

def has_ffmpeg():
    """Comprueba si ffmpeg está instalado en el sistema."""
    try:
        r = subprocess.run(["ffmpeg", "-version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def get_local_ip():
    """Detecta la IP local del iPhone usando un socket UDP temporal (no envía datos reales)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_media_files():
    """Devuelve una lista de archivos multimedia en la carpeta downloads/, ordenados por fecha."""
    files = []
    try:
        if os.path.isdir(DOWNLOADS_DIR):
            for f in os.listdir(DOWNLOADS_DIR):
                ext = os.path.splitext(f)[1].lower()
                fpath = os.path.join(DOWNLOADS_DIR, f)
                if ext in MEDIA_EXTENSIONS and os.path.isfile(fpath):
                    size = os.path.getsize(fpath)
                    mtime = os.path.getmtime(fpath)
                    files.append((f, size, mtime))
        files.sort(key=lambda x: x[2], reverse=True)  # Más reciente primero
    except Exception:
        pass
    return files

def format_size(size_bytes):
    """Convierte bytes a un string legible (MB, KB...)."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"

def build_html(message="", message_type="info"):
    """Construye el HTML de la interfaz concatenando strings para evitar KeyError con llaves CSS."""
    media_files = get_media_files()

    # --- Bloque de mensaje (éxito o error) ---
    msg_block = ""
    if message:
        if message_type == "error":
            color = "#ff5555"
            icon = "⚠️"
        else:
            color = "#50fa7b"
            icon = "✅"
        msg_block = (
            "<div style=\"margin: 20px 0; padding: 14px 18px; border-radius: 10px; "
            "background: rgba(255,255,255,0.05); border-left: 4px solid " + color + "; "
            "color: " + color + "; font-size: 14px; word-break: break-all;\">"
            + icon + " " + message +
            "</div>"
        )

    # --- Lista de archivos descargados ---
    if media_files:
        files_html = (
            "<div style=\"margin-top: 10px;\">"
        )
        for fname, fsize, _ in media_files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in ('.mp3', '.m4a', '.opus'):
                icon = "🎵"
                badge_color = "#bd93f9"
            else:
                icon = "🎬"
                badge_color = "#ff79c6"
            
            encoded_name = urllib.parse.quote(fname)
            files_html += (
                "<a href=\"/files/" + encoded_name + "\" download style=\""
                "display: flex; align-items: center; justify-content: space-between; "
                "text-decoration: none; background: rgba(255,255,255,0.04); "
                "border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; "
                "padding: 12px 16px; margin-bottom: 10px; "
                "transition: background 0.2s;\">"
                "<span style=\"color: #f8f8f2; font-size: 14px; word-break: break-all;\">"
                + icon + " " + fname +
                "</span>"
                "<span style=\"color: " + badge_color + "; font-size: 12px; "
                "font-weight: bold; white-space: nowrap; margin-left: 12px;\">"
                + format_size(fsize) +
                "</span>"
                "</a>"
            )
        files_html += "</div>"
    else:
        files_html = (
            "<div style=\"text-align: center; padding: 40px 20px; "
            "color: rgba(255,255,255,0.3); font-size: 15px;\">"
            "📂 Aún no hay archivos descargados. ¡Pega una URL y empieza!"
            "</div>"
        )

    # --- HTML Principal ---
    html = (
        "<!DOCTYPE html>\n"
        "<html lang=\"es\">\n"
        "<head>\n"
        "    <meta charset=\"UTF-8\">\n"
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, user-scalable=no\">\n"
        "    <title>Downloader Box</title>\n"
        "    <style>\n"
        "        * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "        body { font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', sans-serif; "
        "background: #0f1117; color: #f8f8f2; min-height: 100vh; padding: 24px 16px; }\n"
        "        .container { max-width: 680px; margin: 0 auto; }\n"
        "        .header { text-align: center; margin-bottom: 32px; }\n"
        "        .header h1 { font-size: 26px; font-weight: 700; letter-spacing: -0.5px; }\n"
        "        .header h1 span { background: linear-gradient(90deg, #bd93f9, #ff79c6); "
        "-webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }\n"
        "        .header p { color: rgba(255,255,255,0.4); font-size: 14px; margin-top: 6px; }\n"
        "        .card { background: #1a1d2e; border: 1px solid rgba(255,255,255,0.07); "
        "border-radius: 16px; padding: 24px; margin-bottom: 20px; }\n"
        "        .card h2 { font-size: 16px; font-weight: 600; color: rgba(255,255,255,0.6); "
        "text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }\n"
        "        .url-input { width: 100%; background: rgba(255,255,255,0.06); border: 1px solid "
        "rgba(255,255,255,0.12); border-radius: 10px; color: #f8f8f2; font-size: 15px; "
        "padding: 14px 16px; outline: none; -webkit-appearance: none; margin-bottom: 16px; }\n"
        "        .url-input:focus { border-color: #bd93f9; }\n"
        "        .url-input::placeholder { color: rgba(255,255,255,0.25); }\n"
        "        .btn-group { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }\n"
        "        .btn { border: none; border-radius: 10px; padding: 14px 10px; "
        "font-size: 15px; font-weight: 600; cursor: pointer; transition: opacity 0.2s, transform 0.1s; }\n"
        "        .btn:active { transform: scale(0.97); opacity: 0.85; }\n"
        "        .btn-video { background: linear-gradient(135deg, #ff79c6, #bd93f9); color: #fff; }\n"
        "        .btn-audio { background: linear-gradient(135deg, #50fa7b, #8be9fd); color: #0f1117; }\n"
        "        .btn-update { background: rgba(255,255,255,0.07); color: rgba(255,255,255,0.6); "
        "border: 1px solid rgba(255,255,255,0.12); font-size: 13px; padding: 10px 16px; "
        "border-radius: 8px; cursor: pointer; width: 100%; margin-top: 12px; }\n"
        "        .btn-update:hover { background: rgba(255,255,255,0.11); color: #fff; }\n"
        "        .section-title { font-size: 16px; font-weight: 600; color: rgba(255,255,255,0.6); "
        "text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }\n"
        "        .badge { display: inline-block; padding: 2px 8px; border-radius: 20px; "
        "font-size: 11px; background: rgba(255,255,255,0.08); color: rgba(255,255,255,0.5); "
        "margin-left: 8px; }\n"
        "    </style>\n"
        "</head>\n"
        "<body>\n"
        "    <div class=\"container\">\n"
        "        <div class=\"header\">\n"
        "            <h1>📦 Downloader<span>Box</span></h1>\n"
        "            <p>YouTube · TikTok · Instagram · Twitter/X · y más</p>\n"
        "        </div>\n"
        + msg_block +
        "        <div class=\"card\">\n"
        "            <h2>Nueva Descarga</h2>\n"
        "            <form action=\"/download\" method=\"POST\">\n"
        "                <input class=\"url-input\" type=\"text\" name=\"url\" "
        "placeholder=\"Pega aquí la URL del vídeo o audio...\" autocomplete=\"off\" autocorrect=\"off\" "
        "autocapitalize=\"off\" spellcheck=\"false\" required>\n"
        "                <div class=\"btn-group\">\n"
        "                    <button type=\"submit\" name=\"type\" value=\"video\" class=\"btn btn-video\">"
        "🎬 Descargar Vídeo (MP4)</button>\n"
        "                    <button type=\"submit\" name=\"type\" value=\"audio\" class=\"btn btn-audio\">"
        "🎵 Extraer Audio (MP3)</button>\n"
        "                </div>\n"
        "            </form>\n"
        "            <form action=\"/update-ytdlp\" method=\"POST\" style=\"margin-top: 12px;\">\n"
        "                <button type=\"submit\" class=\"btn btn-update\">🔄 Actualizar yt-dlp (soluciona errores TikTok/IG)</button>\n"
        "            </form>\n"
        "        </div>\n"
        "        \n"
        "        <div class=\"card\">\n"
        "            <p class=\"section-title\">Archivos Descargados"
        "<span class=\"badge\">" + str(len(media_files)) + " archivo(s)</span></p>\n"
        + files_html +
        "        </div>\n"
        "    </div>\n"
        "</body>\n"
        "</html>"
    )
    return html

class DownloaderHandler(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format_str, *args):
        """Silencia los logs por defecto del servidor para una terminal más limpia."""
        pass

    def do_GET(self):
        # --- Servir archivos de la carpeta downloads/ ---
        if self.path.startswith('/files/'):
            filename = urllib.parse.unquote(self.path[len('/files/'):])
            # Seguridad: evitar path traversal
            filename = os.path.basename(filename)
            filepath = os.path.join(DOWNLOADS_DIR, filename)
            
            if os.path.isfile(filepath):
                ext = os.path.splitext(filename)[1].lower()
                content_types = {
                    '.mp4': 'video/mp4', '.mkv': 'video/x-matroska',
                    '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4',
                    '.webm': 'video/webm', '.opus': 'audio/ogg'
                }
                ctype = content_types.get(ext, 'application/octet-stream')
                
                try:
                    filesize = os.path.getsize(filepath)
                    self.send_response(200)
                    self.send_header('Content-Type', ctype)
                    # attachment → el navegador lo descarga directamente al dispositivo
                    self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                    self.send_header('Content-Length', str(filesize))
                    self.end_headers()
                    with open(filepath, 'rb') as fh:
                        # Servir en bloques para no saturar la RAM con archivos grandes
                        while True:
                            chunk = fh.read(65536)  # 64 KB por chunk
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                except BrokenPipeError:
                    pass  # El usuario canceló la descarga, es normal
                except Exception as e:
                    print(f"[!] Error sirviendo archivo: {e}")
            else:
                self.send_response(404)
                self.end_headers()
            return

        # --- Servir la interfaz web principal ---
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(build_html().encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/download':
            # --- Leer y parsear el body del formulario POST manualmente ---
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = b""
            if content_length > 0:
                raw_body = self.rfile.read(content_length)

            parsed = urllib.parse.parse_qs(raw_body.decode('utf-8', errors='ignore'))
            url_list = parsed.get('url', [''])
            type_list = parsed.get('type', ['video'])
            
            url = url_list[0].strip() if url_list else ''
            dl_type = type_list[0].strip() if type_list else 'video'

            message = ""
            message_type = "info"

            if not url:
                message = "Error: No se proporcionó ninguna URL."
                message_type = "error"
            else:
                try:
                    # Crear carpeta de descargas si no existe
                    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
                    output_template = os.path.join(DOWNLOADS_DIR, "%(title)s.%(ext)s")

                    # Detectar si ffmpeg está disponible
                    ffmpeg_ok = has_ffmpeg()
                    print(f"[*] ffmpeg disponible: {ffmpeg_ok}")

                    # Flags de robustez comunes
                    common_flags = [
                        "--no-playlist",
                        "--extractor-retries", "3",
                        "--retries", "5",
                        "--fragment-retries", "5",
                        "--socket-timeout", "30",
                        "--extractor-args", "youtube:player_client=ios,mweb",
                        "-o", output_template,
                    ]

                    if dl_type == 'audio':
                        cmd = (
                            ["yt-dlp"]
                            + common_flags
                            + ["--extract-audio", "--audio-format", "mp3",
                               "--audio-quality", "0", url]
                        )
                        print(f"[*] Extrayendo audio de: {url}")
                    else:
                        if ffmpeg_ok:
                            # Con ffmpeg: mejor vídeo + mejor audio → fusión en mp4
                            # El cliente iOS ya evita AV1, no hace falta restringir el codec
                            cmd = (
                                ["yt-dlp"]
                                + common_flags
                                + ["-f", "bestvideo+bestaudio/best",
                                   "--merge-output-format", "mp4",
                                   "--no-mtime", url]
                            )
                            print(f"[*] Descargando vídeo con ffmpeg de: {url}")
                        else:
                            # Sin ffmpeg: formato pre-fusionado (vídeo+audio en un solo archivo)
                            # Prioridad: mp4 nativo → webm → cualquier cosa disponible
                            cmd = (
                                ["yt-dlp"]
                                + common_flags
                                + ["-f", "best[ext=mp4]/best",
                                   "--no-mtime", url]
                            )
                            print(f"[*] Descargando vídeo pre-fusionado (sin ffmpeg) de: {url}")

                    # Ejecutar descarga (síncrono, máx 10 min)
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=600
                    )

                    if result.returncode == 0:
                        # Encontrar el archivo recién descargado (el más nuevo en downloads/)
                        downloaded_file = None
                        try:
                            files_in_dir = [
                                f for f in os.listdir(DOWNLOADS_DIR)
                                if os.path.splitext(f)[1].lower() in MEDIA_EXTENSIONS
                            ]
                            if files_in_dir:
                                files_in_dir.sort(
                                    key=lambda f: os.path.getmtime(os.path.join(DOWNLOADS_DIR, f)),
                                    reverse=True
                                )
                                downloaded_file = files_in_dir[0]
                        except Exception:
                            pass

                        print(f"[+] Descarga completada: {downloaded_file}")

                        if downloaded_file:
                            # Redirigir al navegador a /files/nombre → descarga automática al dispositivo
                            encoded = urllib.parse.quote(downloaded_file)
                            self.send_response(303)
                            self.send_header('Location', f'/files/{encoded}')
                            self.end_headers()
                            return
                        else:
                            message = "¡Descarga completada! (No se pudo detectar el archivo automáticamente)"
                            message_type = "info"
                    else:
                        stderr_clean = result.stderr.strip().split('\n')[-1] if result.stderr.strip() else "Código de retorno no cero."
                        message = f"Error en yt-dlp: {stderr_clean}"
                        message_type = "error"
                        print(f"[!] Error yt-dlp: {result.stderr.strip()}")

                except FileNotFoundError:
                    message = "Error crítico: 'yt-dlp' no está instalado. Ejecuta: pip install yt-dlp"
                    message_type = "error"
                    print("[!] yt-dlp no encontrado.")
                except subprocess.TimeoutExpired:
                    message = "Error: La descarga ha superado el tiempo máximo de 10 minutos."
                    message_type = "error"
                    print("[!] Timeout en la descarga.")
                except Exception as e:
                    message = f"Error inesperado: {str(e)}"
                    message_type = "error"
                    print(f"[!] Excepción: {e}")

            # Enviar la página con el mensaje de resultado (303 no aplica aquí porque necesitamos el mensaje)
            # Usamos un render directo con mensaje en lugar de redirigir para no perder el contexto del error
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(build_html(message=message, message_type=message_type).encode('utf-8'))
        elif self.path == '/update-ytdlp':
            # Consumir body aunque esté vacío
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                self.rfile.read(content_length)

            # URL del binario oficial de la última versión de yt-dlp en GitHub
            YTDLP_URL = "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp"
            # Destino: sobreescribe el binario existente (apk lo instala en /usr/bin)
            INSTALL_PATHS = ["/usr/local/bin/yt-dlp", "/usr/bin/yt-dlp"]

            print("[*] Descargando la última versión de yt-dlp desde GitHub...")
            message = ""
            message_type = "info"
            try:
                # Detectar dónde está el binario actual para sobreescribirlo
                which_result = subprocess.run(["which", "yt-dlp"], capture_output=True, text=True)
                current_path = which_result.stdout.strip() if which_result.returncode == 0 else INSTALL_PATHS[0]
                if not current_path:
                    current_path = INSTALL_PATHS[0]

                print(f"[*] Instalando en: {current_path}")

                # Intentar con wget primero, luego curl como fallback
                downloaded = False
                dl_error = ""

                # --- Intento 1: wget ---
                try:
                    result_wget = subprocess.run(
                        ["wget", "-q", "-O", current_path, YTDLP_URL],
                        capture_output=True, text=True, timeout=180
                    )
                    if result_wget.returncode == 0:
                        downloaded = True
                    else:
                        dl_error = result_wget.stderr.strip() or "wget falló sin mensaje."
                except FileNotFoundError:
                    dl_error = "wget no disponible."
                except subprocess.TimeoutExpired:
                    dl_error = "wget tardó demasiado."

                # --- Intento 2: curl ---
                if not downloaded:
                    try:
                        result_curl = subprocess.run(
                            ["curl", "-L", "-o", current_path, YTDLP_URL],
                            capture_output=True, text=True, timeout=180
                        )
                        if result_curl.returncode == 0:
                            downloaded = True
                        else:
                            dl_error = result_curl.stderr.strip() or "curl falló sin mensaje."
                    except FileNotFoundError:
                        dl_error = "wget y curl no disponibles. Instala con: apk add wget"
                    except subprocess.TimeoutExpired:
                        dl_error = "curl tardó demasiado."

                if downloaded:
                    # Dar permisos de ejecución al binario descargado
                    subprocess.run(["chmod", "+x", current_path], capture_output=True)
                    # Verificar la versión instalada
                    ver_result = subprocess.run(["yt-dlp", "--version"], capture_output=True, text=True)
                    version_str = ver_result.stdout.strip() if ver_result.returncode == 0 else "desconocida"
                    message = f"✅ yt-dlp actualizado a la versión {version_str} desde GitHub. ¡TikTok e Instagram deberían funcionar ahora!"
                    message_type = "info"
                    print(f"[+] {message}")
                else:
                    message = f"Error al descargar yt-dlp: {dl_error}"
                    message_type = "error"
                    print(f"[!] {message}")

            except Exception as e:
                message = f"Error inesperado al actualizar: {str(e)}"
                message_type = "error"
                print(f"[!] {message}")

            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(build_html(message=message, message_type=message_type).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()


def run():
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), DownloaderHandler) as httpd:
        local_ip = get_local_ip()
        print(f"\n🚀 Downloader Box activo. Abre en tu navegador: http://{local_ip}:{PORT}")
        print(f"   Archivos descargados en: {os.path.abspath('.')}")
        print("   Presiona Ctrl+C para detener.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Downloader Box detenido de forma segura.")


if __name__ == "__main__":
    run()
