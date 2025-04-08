# Complete Utility App
# Copyright (C) 2025  Ishant Singh (0pen-sourcer)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import re
import json
import threading
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter import (
    Tk, Label, Button, Entry, StringVar, filedialog, messagebox,
    Text, Scrollbar, Frame, simpledialog, Toplevel, Menu, Checkbutton, BooleanVar
)
from tkinter import ttk
import img2pdf
from yt_dlp import YoutubeDL
from youtube_transcript_api import YouTubeTranscriptApi
import speech_recognition as sr
from pydub import AudioSegment
from PyPDF2 import PdfMerger
from themes import ThemeManager
from PIL import Image
from datetime import datetime
import sys
import ctypes
import subprocess

#for FFMEG (YT and Universal tools)

try:
    import ffmpeg
except ImportError:
    ffmpeg = None

# For OCR (Extra Tools)
try:
    import pytesseract
except ImportError:
    pytesseract = None

if getattr(sys, 'frozen', False):
 
    base_path = os.path.dirname(sys.executable)
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

# For encryption/decryption (Extra Tools)
try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None

pytesseract.pytesseract.tesseract_cmd = os.path.join(base_path, 'tesseract', 'tesseract.exe')
ffmpeg_path = os.path.join(base_path, 'ffmpeg', 'bin', 'ffmpeg.exe')

#############################################
# Global Configuration Dictionary
#############################################
config = {
    "screen_size": "Medium",  # Options: Small, Medium, Large
    "text_color": "Black",  # Options: Black, White, Blue, etc.
    "theme": "Classic"  # Options: Classic, Dark, Bright
}

#############################################
# Folder Structure & Configuration (Version 1.0)
#############################################
def get_base_folder():
    config_path = os.path.join(os.path.expanduser("~"), ".utility_app_config")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                conf = json.load(f)
            if "base_folder" in conf:
                base = conf["base_folder"]
                os.makedirs(base, exist_ok=True)
                return base
        except Exception as e:
            log_error(f"Error reading base folder from config: {e}")
    # Fallback default
    documents = os.path.join(os.path.expanduser("~"), "Documents")
    base = os.path.join(documents, "Complete Utility App")
    os.makedirs(base, exist_ok=True)
    return base

def get_yt_folder():
    folder = os.path.join(get_base_folder(), "YT Downloads")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_yt_transcription_folder():
    folder = os.path.join(get_yt_folder(), "yt_transcriptions")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_univ_folder():
    folder = os.path.join(get_base_folder(), "Universal Downloads")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_univ_transcription_folder():
    folder = os.path.join(get_univ_folder(), "universal_transcriptions")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_encryption_folder():
    folder = os.path.join(get_base_folder(), "Encrypted Files")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_resized_images_folder():
    folder = os.path.join(get_base_folder(), "Resized Images")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_converted_pdfs_folder():
    folder = os.path.join(get_base_folder(), "Converted PDFs")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_merged_pdfs_folder():
    folder = os.path.join(get_base_folder(), "Merged PDFs")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_split_pdfs_folder():
    folder = os.path.join(get_base_folder(), "Split PDFs")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_trimmed_audio_folder():
    folder = os.path.join(get_base_folder(), "Trimmed Audio")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_qr_codes_folder():
    folder = os.path.join(get_base_folder(), "QR Codes")
    os.makedirs(folder, exist_ok=True)
    return folder
def get_decrypted_key_folder():
    folder = os.path.join(get_base_folder(), "Decryted Key")
    os.makedirs(folder, exist_ok=True)
    return folder


# Save encryption keys in the base folder
KEYS_JSON = os.path.join(get_base_folder(), "keys.json")
if not os.path.exists(KEYS_JSON):
    with open(KEYS_JSON, "w") as f:
        json.dump({}, f)

THEME_JSON = os.path.join(get_base_folder(), "theme_config.json")
def save_theme_preference(theme):
    with open(THEME_JSON, 'w') as f:
        json.dump({"theme": theme}, f)

def load_theme_preference():
    if os.path.exists(THEME_JSON):
        with open(THEME_JSON, 'r') as f:
            config = json.load(f)
            return config.get("theme", "Classic")  
    return "Classic"

SCREEN_SIZE_JSON = os.path.join(get_base_folder(), "screen_size_config.json")
def save_screen_size_preference(screen_size):
    with open(SCREEN_SIZE_JSON, 'w') as f:
        json.dump({"screen_size": screen_size}, f)

def load_screen_size_preference():
    if os.path.exists(SCREEN_SIZE_JSON):
        with open(SCREEN_SIZE_JSON, 'r') as f:
            data = json.load(f)
        return data.get("screen_size", "Medium")
    return "Medium"


#############################################
# Logging Function
#############################################
def log_error(message):
    print("[ERROR]", message)
    log_file = os.path.join(get_base_folder(), "app_log.txt")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(message + "\n")


#############################################
# Tooltip Class
#############################################
class Tooltip:
    """Simple tooltip for a widget."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.widget.bind("<Enter>", self.show)
        self.widget.bind("<Leave>", self.hide)

    def show(self, event=None):
        if self.tipwindow or not self.text:
            return
        bbox = self.widget.bbox("insert")
        if bbox:
            x, y, _cx, cy = bbox
        else:
            x, y, cy = 0, 0, 0
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 20
        self.tipwindow = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = Label(tw, text=self.text, justify='left',
                      background="#ffffe0", relief='solid', borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide(self, event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
        self.tipwindow = None


#############################################
# Audio Conversion (Simpler Version)
#############################################
def convert_audio_to_wav(mp3_path, wav_path):
    try:
        # Use the explicitly defined ffmpeg_path variable in the command
        command = [ffmpeg_path, '-y', '-i', mp3_path, wav_path]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"FFmpeg conversion error: {result.stderr}")
        print("Audio converted to WAV successfully.")
    except Exception as e:
        print("Error during audio conversion:", str(e))
        raise

#############################################
# Base Class for Download & Transcribe (shared by YT & Universal)
#############################################
class BaseDownloadFrame(Frame):
    """Shared functionality for downloading media and transcribing."""

    def update_progress_bar(self, d):
        if d.get('status') == 'downloading':
            percent_str = d.get('_percent_str', '0.0%').strip()
            try:
                percent = float(percent_str.strip('%'))
            except ValueError:
                percent = 0
            self.after(0, lambda: self.progress_bar.config(value=percent))
        elif d.get('status') == 'finished':
            self.after(0, lambda: self.progress_bar.config(value=100))

    def extract_video_id(self, url):
        """Extract the video ID from various YouTube URL formats."""
        video_id = None
        if "youtube.com/shorts/" in url:
            parts = url.split("youtube.com/shorts/")
            if len(parts) > 1:
                video_id = parts[1].split("?")[0]
        elif "v=" in url:
            match = re.search(r"v=([^&]+)", url)
            if match:
                video_id = match.group(1)
        else:
            video_id = url.rstrip("/").split("/")[-1]
        return video_id

    def transcribe_audio(self, audio_path):
        recognizer = sr.Recognizer()
        with sr.AudioFile(audio_path) as source:
            audio_data = recognizer.record(source)
        try:
            return recognizer.recognize_google(audio_data)
        except sr.UnknownValueError:
            return "Could not understand audio."
        except sr.RequestError:
            return "Could not connect to API server"


#############################################
# Security Configuration & Key Management
#############################################
class SecurityManager:
    def __init__(self):
        self.master_password_hash = None
        self.salt = None
        self.fernet = None
        self.load_security_config()

    def load_security_config(self):
        config_path = os.path.join(get_base_folder(), "security_config.json")
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = json.load(f)
                self.master_password_hash = config.get("master_password_hash")
                salt_str = config.get("salt", "")
                if salt_str:
                    self.salt = base64.b64decode(salt_str)

    def save_security_config(self):
        config_path = os.path.join(get_base_folder(), "security_config.json")
        config = {
            "master_password_hash": self.master_password_hash,
            "salt": base64.b64encode(self.salt).decode() if self.salt else None
        }
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

    def set_master_password(self, password):
        # Keep a copy of the old fernet (if any) to decrypt existing keys.
        old_fernet = self.fernet

        # Generate new salt and hash the new password
        self.salt = os.urandom(16)
        self.master_password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            self.salt,
            100000
        ).hex()
        self.save_security_config()
        
        # Initialize new Fernet with the new password
        self._init_fernet(password)
        
        # Re-encrypt keys using the old fernet to decrypt if possible, then reencrypt with the new fernet.
        self._reencrypt_keys(old_fernet)

    
    def verify_password(self, password):
        if not self.master_password_hash or not self.salt:
            return False
        test_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            self.salt,
            100000
        ).hex()
        return test_hash == self.master_password_hash

    def _init_fernet(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(key)

    def _reencrypt_keys(self, old_fernet=None):
        if not os.path.exists(KEYS_JSON):
            return
        try:
            with open(KEYS_JSON, "r") as f:
                keys = json.load(f)
            new_encrypted_keys = {}

            for filename, key in keys.items():
                if old_fernet:
                    try:
                    # MUST succeed if it's truly old ciphertext
                        decrypted = old_fernet.decrypt(key.encode()).decode()
                    except Exception as e:
                    # If decryption fails, raise an error or log it
                        raise ValueError(
                        f"Failed to decrypt '{filename}' with old master password. "
                        f"Data may be corrupted or the old password is incorrect.\n{e}"
                        )
                else:
                # If this is the very first time you’re encrypting plaintext keys
                # (i.e., there is no old Fernet), treat them as plaintext.
                    decrypted = key

            # Encrypt with the new Fernet
                new_encrypted_keys[filename] = self.encrypt_key(decrypted)

            with open(KEYS_JSON, "w") as f:
                json.dump(new_encrypted_keys, f, indent=2)
        except Exception as e:
            log_error(f"Error reencrypting keys: {e}")


    def encrypt_key(self, key_data):
        if not self.fernet:
            raise ValueError("Fernet not initialized. Set master password first.")
        return self.fernet.encrypt(key_data.encode()).decode()

    def decrypt_key(self, encrypted_key):
        if not self.fernet:
            raise ValueError("Fernet not initialized. Verify master password first.")
        return self.fernet.decrypt(encrypted_key.encode()).decode()

    def reveal_keys(self, password):
        """
        Reveals the plaintext keys from KEYS_JSON after verifying the master password.
        """
        if not self.verify_password(password):
            raise ValueError("Incorrect master password.")
        # Reinitialize fernet with the provided password to ensure we use the correct key.
        self._init_fernet(password)
        if not os.path.exists(KEYS_JSON):
            return {}
        try:
            with open(KEYS_JSON, "r") as f:
                encrypted_keys = json.load(f)
            decrypted_keys = {}
            for filename, key in encrypted_keys.items():
                decrypted_keys[filename] = self.decrypt_key(key)
            return decrypted_keys
        except Exception as e:
            log_error(f"Error revealing keys: {e}")
            return {}

# Initialize global security manager
security_manager = SecurityManager()


#############################################
# Tab 1: YouTube Downloader & Transcriber
#############################################
class YouTubeFrame(BaseDownloadFrame):
    def __init__(self, parent):
        super().__init__(parent, padx=10, pady=10)
        self.url_var = StringVar()
        self.download_folder = StringVar(value=get_yt_folder())

        Label(self, text="YouTube Downloader & Transcriber", font=("Arial", 16)).pack(pady=10)
        Label(self, text="Enter YouTube URL:").pack(pady=5)
        self.url_entry = Entry(self, textvariable=self.url_var, width=60)
        self.url_entry.pack(pady=5)
        self.url_entry.bind("<Button-3>", self.show_url_context_menu)

        Button(self, text="Select Folder", command=self.select_folder).pack(pady=5)
        Label(self, textvariable=self.download_folder, fg="blue").pack(pady=5)

        Label(self, text="Select Download Type:").pack(pady=5)
        self.download_type = ttk.Combobox(self, values=["Audio Only", "Video Only", "Audio+Video"], state="readonly")
        self.download_type.set("Audio+Video")
        self.download_type.pack(pady=5)
        self.download_type.bind("<<ComboboxSelected>>", self.toggle_extra_options)

        options_frame = Frame(self)
        options_frame.pack(pady=5, fill="x")

        # Create a container frame for the three options that will center them
        options_container = Frame(options_frame)
        options_container.pack(expand=True)

        # Configure grid weights to ensure proper centering
        options_container.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        Label(options_container, text="Select Resolution:").grid(row=0, column=0, padx=5)
        self.resolution = ttk.Combobox(options_container,
                                       values=["144p", "360p", "480p", "720p", "1080p", "4K", "8K"],
                                       state="readonly", width=15)
        self.resolution.set("1080p")
        self.resolution.grid(row=0, column=1, padx=5)

        Label(options_container, text="Select Audio Quality:").grid(row=0, column=2, padx=5)
        self.audio_quality = ttk.Combobox(options_container, values=["Auto", "128", "192", "320"],
                                          state="readonly", width=15)
        self.audio_quality.set("Auto")
        self.audio_quality.grid(row=0, column=3, padx=5)

        Label(options_container, text="Output Format:").grid(row=0, column=4, padx=5)
        self.output_format = ttk.Combobox(options_container, values=["MP4", "WEBM"],
                                          state="readonly", width=15)
        self.output_format.set("MP4")
        self.output_format.grid(row=0, column=5, padx=5)

        btn_frame = Frame(self)
        btn_frame.pack(pady=10)
        self.download_btn = Button(btn_frame, text="Download Media", command=self.download_media)
        self.download_btn.pack(side="left", padx=5)
        self.transcribe_btn = Button(btn_frame, text="Transcribe Only", command=self.transcribe_only)
        self.transcribe_btn.pack(side="left", padx=5)

        self.progress_bar = ttk.Progressbar(self, orient="horizontal", length=400, mode="determinate",
                                            style="green.Horizontal.TProgressbar")
        self.progress_bar.pack(pady=10)

        Label(self, text="Transcript Output:").pack(pady=5)
        transcript_frame = Frame(self)
        transcript_frame.pack(pady=5)
        self.transcript_text = Text(transcript_frame, height=10, width=70, wrap="word")
        self.transcript_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = Scrollbar(transcript_frame, command=self.transcript_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.transcript_text.config(yscrollcommand=scrollbar.set)

        final_btn_frame = Frame(self)
        final_btn_frame.pack(pady=10)
        Button(final_btn_frame, text="Copy Transcript", command=self.copy_transcript).pack(side="left", padx=5)
        Button(final_btn_frame, text="Download Transcript", command=self.download_transcript).pack(side="left", padx=5)

    ###################################################
    # 1. Simple Helper Function to Check YouTube Links #
    ###################################################
    def is_valid_youtube_link(self, url):
        # Convert to lowercase and strip whitespace
        url = url.lower().strip()
        # Must contain "youtube.com" or "youtu.be"
        if "youtube.com" not in url and "youtu.be" not in url:
            return False
        # Must have either "?v=" (watch link) or "/shorts/"
        if "?v=" in url or "/shorts/" in url or "youtu.be/" in url:
            return True
        return False

    def toggle_extra_options(self, event=None):
        mode = self.download_type.get()
        self.resolution.config(state="readonly" if mode in ["Video Only", "Audio+Video"] else "disabled")
        self.audio_quality.config(state="readonly" if mode in ["Audio Only", "Audio+Video"] else "disabled")
        self.output_format.config(state="readonly" if mode in ["Video Only", "Audio+Video"] else "disabled")

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.download_folder.set(folder)
        else:
            self.download_folder.set(get_yt_folder())

    ############################################
    # 2. Validate URL Before Downloading Media #
    ############################################
    def download_media(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a YouTube URL")
            return

        if not self.is_valid_youtube_link(url):
            messagebox.showerror("Error", "Only standard YouTube links or Shorts are allowed!")
            return

        if not self.download_folder.get():
            self.download_folder.set(get_yt_folder())
        self.download_btn.config(state="disabled")
        self.transcribe_btn.config(state="disabled")
        threading.Thread(target=self._download_media, daemon=True).start()

    def _download_media(self):
        try:
            url = self.url_var.get().strip()
            output_path = self.download_folder.get()
            mode = self.download_type.get()
            res = self.resolution.get() if mode in ["Video Only", "Audio+Video"] else None
            aq = self.audio_quality.get() if mode in ["Audio Only", "Audio+Video"] else "Auto"
            fmt = self.output_format.get().lower() if mode in ["Video Only", "Audio+Video"] else None

            ydl_opts = {
                'outtmpl': os.path.join(output_path, '%(title)s.%(ext)s'),
                'progress_hooks': [self.update_progress_bar],
                'noplaylist': True,
                'merge_output_format': fmt if fmt in ["mp4", "webm"] else None,
                'ffmpeg_location': os.path.join(base_path, 'ffmpeg', 'bin')  # <-- Added FFmpeg location here
            }
            if mode == "Audio Only":
                pp = {"key": "FFmpegExtractAudio", "preferredcodec": "mp3"}
                if aq != "Auto":
                    pp["preferredquality"] = aq
                ydl_opts['postprocessors'] = [pp]
                ydl_opts['format'] = 'bestaudio'
            elif mode == "Video Only":
                if res:
                    h = re.sub(r'\D', '', res)
                    ydl_opts['format'] = f"bestvideo[height<={h}]"
                else:
                    ydl_opts['format'] = 'bestvideo'
            elif mode == "Audio+Video":
                if res:
                    h = re.sub(r'\D', '', res)
                    ydl_opts['format'] = f"bestvideo[height<={h}]+bestaudio"
                else:
                    ydl_opts['format'] = "bestvideo+bestaudio"
            with YoutubeDL(ydl_opts) as ydl:
                ydl.download([url])
            self.after(0, lambda: messagebox.showinfo("Success", "Download completed successfully!"))
        except Exception as e:
            err = f"Error: {e}"
            log_error(err)
            self.after(0, lambda: messagebox.showerror("Error", err))
        finally:
            self.after(0, lambda: self.download_btn.config(state="normal"))
            self.after(0, lambda: self.transcribe_btn.config(state="normal"))

    ###############################################
    # 3. Validate URL Before Transcribing Only    #
    ###############################################
    def transcribe_only(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a YouTube URL")
            return
        
        if not self.is_valid_youtube_link(url):
            messagebox.showerror("Error", "Only standard YouTube watch links or Shorts are allowed!")
            return

        if not self.download_folder.get():
            self.download_folder.set(get_yt_folder())
        self.download_btn.config(state="disabled")
        self.transcribe_btn.config(state="disabled")
        self.transcript_text.delete("1.0", "end")
        self.transcript_text.insert("1.0", "Transcribing... please wait...")
        threading.Thread(target=self._transcribe_only, daemon=True).start()

    def _transcribe_only(self):
        url = self.url_var.get().strip()
        try:
           
            video_id = self.extract_video_id(url)
            transcript_data = YouTubeTranscriptApi.get_transcript(video_id)
            transcript_text = "\n".join([entry["text"] for entry in transcript_data])
            self.after(0, lambda: self.transcript_text.delete("1.0", "end"))
            self.after(0, lambda: self.transcript_text.insert("1.0", transcript_text))
        except Exception as api_error:
            log_error(f"Transcript API failed: {api_error}")
            try:
                output_folder = self.download_folder.get()
                audio_path = os.path.join(output_folder, "audio_temp.mp3")
                ydl_opts = {
                    'format': 'bestaudio',
                    'postprocessors': [{"key": "FFmpegExtractAudio", "preferredcodec": "mp3"}],
                    'outtmpl': audio_path,
                    'noplaylist': True,
                }
                with YoutubeDL(ydl_opts) as ydl:
                    ydl.download([url])
                if not os.path.exists(audio_path):
                    if os.path.exists(audio_path + ".mp3"):
                        audio_path = audio_path + ".mp3"
                    else:
                        raise FileNotFoundError(f"{audio_path} not found.")
                wav_path = os.path.join(os.path.dirname(audio_path), "converted_temp.wav")
                convert_audio_to_wav(audio_path, wav_path)
                transcript = self.transcribe_audio(wav_path)
                self.after(0, lambda: self.transcript_text.delete("1.0", "end"))
                self.after(0, lambda: self.transcript_text.insert("1.0", transcript))
                if os.path.exists(audio_path):
                    os.remove(audio_path)
                if os.path.exists(wav_path):
                    os.remove(wav_path)
            except Exception as audio_error:
                err = f"Audio transcription error: {audio_error}"
                log_error(err)
                self.after(0, lambda: self.transcript_text.delete("1.0", "end"))
                self.after(0, lambda: self.transcript_text.insert("1.0", err))
        finally:
            self.after(0, lambda: self.download_btn.config(state="normal"))
            self.after(0, lambda: self.transcribe_btn.config(state="normal"))

    def copy_transcript(self):
        transcript = self.transcript_text.get("1.0", "end").strip()
        if transcript:
            self.clipboard_clear()
            self.clipboard_append(transcript)
            messagebox.showinfo("Copied", "Transcript copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No transcript available to copy.")

    def download_transcript(self):
        transcript = self.transcript_text.get("1.0", "end").strip()
        if transcript:
            default_dir = get_yt_transcription_folder()
            file_path = filedialog.asksaveasfilename(initialdir=default_dir, defaultextension=".txt",
                                                     filetypes=[("Text files", "*.txt")],
                                                     title="Save Transcript As")
            if file_path:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(transcript)
                    messagebox.showinfo("Saved", f"Transcript saved to {file_path}")
                except Exception as e:
                    err = f"Error: {e}"
                    messagebox.showerror("Error", err)
        else:
            messagebox.showwarning("Warning", "No transcript available to save.")

    def show_url_context_menu(self, event):
        context_menu = Menu(self, tearoff=0)
        context_menu.add_command(label="Paste", command=lambda: self.url_entry.event_generate("<<Paste>>"))
        context_menu.tk_popup(event.x_root, event.y_root)
        context_menu.grab_release()

#############################################
# Tab 3: Media Tools (Images, PDFs & Renaming)
#############################################
class MediaToolsFrame(Frame):
    def __init__(self, parent):
        super().__init__(parent, padx=10, pady=10)  
        
        # Main title
        Label(self, text="Media Tools", font=("Arial", 16)).pack(pady=10)

        # Image Tools Section
        Label(self, text="Image Tools:", font=("Arial", 12)).pack(pady=(20,5))
        
        img_btn_frame = Frame(self)
        img_btn_frame.pack(pady=5)
        Button(img_btn_frame, text="Convert Images to PDF", command=self.convert_images_to_pdf).pack(side="left", padx=5)
        Button(img_btn_frame, text="Resize Images", command=self.resize_images).pack(side="left", padx=5)
        Button(img_btn_frame, text="Convert Image Format", command=self.convert_image_format).pack(side="left", padx=5)  # Add this line
        
        img_hint = Label(self, text="?", fg="blue", cursor="question_arrow")
        img_hint.pack(pady=5)
        Tooltip(img_hint, "Convert multiple images to PDF, resize images, or convert image formats (JPG, PNG, BMP, GIF, WEBP, TIFF) in batch.")

        # PDF Tools Section
        Label(self, text="PDF Tools:", font=("Arial", 12)).pack(pady=(20,5))
        
        pdf_btn_frame = Frame(self)
        pdf_btn_frame.pack(pady=5)
        Button(pdf_btn_frame, text="Merge PDFs", command=self.merge_pdfs).pack(side="left", padx=5)
        Button(pdf_btn_frame, text="Split PDF", command=self.split_pdf).pack(side="left", padx=5)
        
        pdf_hint = Label(self, text="?", fg="blue", cursor="question_arrow")
        pdf_hint.pack(pady=5)
        Tooltip(pdf_hint, "Merge multiple PDFs into one file or split a PDF into multiple files.\nSpecify page ranges for splitting.")

        # Audio Tools Section
        Label(self, text="Audio Tools:", font=("Arial", 12)).pack(pady=(20,5))
        
        audio_btn_frame = Frame(self)
        audio_btn_frame.pack(pady=5)
        Button(audio_btn_frame, text="Trim Audio", command=self.trim_audio).pack(side="left", padx=5)
        
        audio_hint = Label(self, text="?", fg="blue", cursor="question_arrow")
        audio_hint.pack(pady=5)
        Tooltip(audio_hint, "Trim audio files by specifying start and end times.\nSupported formats: MP3, WAV, OGG, M4A")

        # QR Code Tools Section
        Label(self, text="QR Code Generator:", font=("Arial", 12)).pack(pady=(20,5))
        
        qr_btn_frame = Frame(self)
        qr_btn_frame.pack(pady=5)
        Button(qr_btn_frame, text="Generate QR Code", command=self.generate_qr).pack(side="left", padx=5)
        
        qr_hint = Label(self, text="?", fg="blue", cursor="question_arrow")
        qr_hint.pack(pady=5)
        Tooltip(qr_hint, "Generate QR codes from text or URLs.\nCustomize size and save as PNG.")

        # Rename Schemes
        self.image_scheme_var = StringVar(value="Numeric")
        self.pdf_scheme_var = StringVar(value="Numeric")
        scheme_frame = Frame(self)
        scheme_frame.pack(pady=5)
        Label(scheme_frame, text="Image Rename Scheme:").grid(row=0, column=0, padx=5)
        self.image_scheme = ttk.Combobox(scheme_frame, textvariable=self.image_scheme_var,
                                         values=["Numeric", "Alphabetic"], state="readonly")
        self.image_scheme.grid(row=0, column=1, padx=5)
        Label(scheme_frame, text="PDF Rename Scheme:").grid(row=0, column=2, padx=5)
        self.pdf_scheme = ttk.Combobox(scheme_frame, textvariable=self.pdf_scheme_var, values=["Numeric", "Alphabetic"],
                                       state="readonly")
        self.pdf_scheme.grid(row=0, column=3, padx=5)

        btn_frame = Frame(self)
        btn_frame.pack(pady=10)
        b1 = Button(btn_frame, text="Rename Images", command=self.rename_images)
        b1.grid(row=0, column=0, padx=5)
        q1 = Label(btn_frame, text="?", fg="blue", cursor="question_arrow")
        q1.grid(row=0, column=1)
        Tooltip(q1, "Rename images sequentially using the selected scheme.")
        
        b2 = Button(btn_frame, text="Rename PDFs", command=self.rename_pdfs)
        b2.grid(row=0, column=2, padx=5)
        q2 = Label(btn_frame, text="?", fg="blue", cursor="question_arrow")
        q2.grid(row=0, column=3)
        Tooltip(q2, "Rename PDFs sequentially using the selected scheme.")

        self.status_label = Label(self, text="", fg="green")
        self.status_label.pack(pady=5)

    def convert_image_format(self):
        try:
            # Prompt user to select an image file
            file_path = filedialog.askopenfilename(
                title="Select Image to Convert",
                filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.gif *.webp *.tiff")]
            )
            if not file_path:
                return

            # Create a dialog for selecting the output format
            format_dialog = Toplevel(self)
            format_dialog.title("Select Output Format")
            format_dialog.geometry("300x150")
            ThemeManager.apply_theme(format_dialog, config.get("theme", "Classic"))

            Label(format_dialog, text="Choose output format:").pack(pady=5)

            # Create a dropdown for format selection
            format_var = StringVar(value="PNG")
            format_options = ["PNG", "JPG", "BMP", "GIF", "WEBP", "TIFF"]
            format_dropdown = ttk.Combobox(format_dialog, textvariable=format_var, values=format_options, state="readonly")
            format_dropdown.pack(pady=5)

            def process_conversion():
                selected_format = format_var.get().lower()  # e.g., "jpg" or "png"
                # For Pillow, if "jpg" is chosen, use "JPEG" instead
                if selected_format == "jpg":
                    pil_format = "JPEG"
                else:
                    pil_format = selected_format.upper()

                output_folder = get_converted_pdfs_folder()  # Adjust to your desired folder
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file_name = f"converted_{timestamp}.{selected_format}"
                output_path = os.path.join(output_folder, output_file_name)

                # Open the image and convert it
                with Image.open(file_path) as img:
                    img.save(output_path, format=pil_format)  # Save in the selected format

                self.status_label.config(text=f"Image converted to {pil_format}!\nSaved as: {output_path}")
                format_dialog.destroy()

            Button(format_dialog, text="Convert", command=process_conversion).pack(pady=10)
            Button(format_dialog, text="Cancel", command=format_dialog.destroy).pack(pady=5)

        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")


    def rename_images(self):
        files = filedialog.askopenfilenames(
            title="Select Images to Rename",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.gif")]
        )
        if not files:
            return
        try:
            scheme = self.image_scheme_var.get()
            i = 1
            for f in files:
                ext = os.path.splitext(f)[1]
                new_name = f"{i}{ext}" if scheme == "Numeric" else f"{chr(64 + i)}{ext}"
                os.rename(f, os.path.join(os.path.dirname(f), new_name))
                i += 1
            self.status_label.config(text="Images renamed successfully!")
        except Exception as e:
            err = f"Error: {e}"
            messagebox.showerror("Error", err)

    def rename_pdfs(self):
        files = filedialog.askopenfilenames(
            title="Select PDFs to Rename",
            filetypes=[("PDF files", "*.pdf")]
        )
        if not files:
            return
        try:
            scheme = self.pdf_scheme_var.get()
            i = 1
            for f in files:
                new_name = f"{i}.pdf" if scheme == "Numeric" else f"{chr(64 + i)}.pdf"
                os.rename(f, os.path.join(os.path.dirname(f), new_name))
                i += 1
            self.status_label.config(text="PDFs renamed successfully!")
        except Exception as e:
            err = f"Error: {e}"
            messagebox.showerror("Error", err)

    def convert_images_to_pdf(self):
        try:
            files = filedialog.askopenfilenames(
                title="Select Images to Convert",
                filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.gif")]
            )
            if not files:
                return
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_pdf = os.path.join(get_converted_pdfs_folder(), f"converted_{timestamp}.pdf")
                
            with open(output_pdf, "wb") as f:
                f.write(img2pdf.convert([f for f in files]))
            self.status_label.config(text=f"Images converted to PDF!\nSaved as: {output_pdf}")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")

    def resize_images(self):
        try:
            files = filedialog.askopenfilenames(
                title="Select Images to Resize",
                filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp")]
            )
            if not files:
                return
            
            # Create themed size dialog
            size_dialog = Toplevel(self)
            size_dialog.title("Resize Images")
            size_dialog.geometry("300x200")
            ThemeManager.apply_theme(size_dialog, config.get("theme", "Classic"))
            
            Label(size_dialog, text="Enter new dimensions:").pack(pady=5)
            
            size_frame = Frame(size_dialog)
            size_frame.pack(pady=5)
            
            Label(size_frame, text="Width:").pack(side="left")
            width_var = StringVar()
            width_entry = Entry(size_frame, textvariable=width_var, width=8)
            width_entry.pack(side="left", padx=5)
            
            Label(size_frame, text="Height:").pack(side="left")
            height_var = StringVar()
            height_entry = Entry(size_frame, textvariable=height_var, width=8)
            height_entry.pack(side="left", padx=5)
            
            def process_resize():
                try:
                    width = int(width_var.get())
                    height = int(height_var.get())
                    
                    output_folder = get_resized_images_folder()
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    
                    for img_file in files:
                        with Image.open(img_file) as img:
                            resized_img = img.resize((width, height), Image.Resampling.LANCZOS)
                            output_path = os.path.join(output_folder, f"resized_{timestamp}_{os.path.basename(img_file)}")
                            resized_img.save(output_path)
                    
                    self.status_label.config(text=f"Images resized and saved in:\n{output_folder}")
                    size_dialog.destroy()
                    
                except ValueError:
                    messagebox.showerror("Error", "Please enter valid numbers for dimensions")
                except Exception as e:
                    messagebox.showerror("Error", f"Error resizing images: {e}")
            
            Button(size_dialog, text="Resize", command=process_resize).pack(pady=10)
            Button(size_dialog, text="Cancel", command=size_dialog.destroy).pack(pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")

    def merge_pdfs(self):
        try:
            files = filedialog.askopenfilenames(
                title="Select PDFs to Merge",
                filetypes=[("PDF files", "*.pdf")]
            )
            if not files:
                return
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_pdf = os.path.join(get_merged_pdfs_folder(), f"merged_{timestamp}.pdf")
                
            merger = PdfMerger()
            for pdf in files:
                merger.append(pdf)
                
            with open(output_pdf, "wb") as merged_pdf:
                merger.write(merged_pdf)
            merger.close()
            
            self.status_label.config(text=f"PDFs merged!\nSaved as: {output_pdf}")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")

    def split_pdf(self):
        try:
            file_path = filedialog.askopenfilename(
                title="Select PDF to split",
                filetypes=[("PDF files", "*.pdf")]
            )
            if not file_path:
                return
            
            # Create themed split dialog
            split_dialog = Toplevel(self)
            split_dialog.title("Split PDF")
            split_dialog.geometry("300x200")
            ThemeManager.apply_theme(split_dialog, config.get("theme", "Classic"))
            
            Label(split_dialog, text="Enter page ranges (e.g., 1-3,4-6):").pack(pady=5)
            
            ranges_var = StringVar()
            Entry(split_dialog, textvariable=ranges_var, width=30).pack(pady=5)
            
            def process_split():
                try:
                    ranges_text = ranges_var.get().strip()
                    if not ranges_text:
                        messagebox.showerror("Error", "Please enter page ranges")
                        return
                    
                    output_folder = get_split_pdfs_folder()
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    
                    ranges = []
                    for r in ranges_text.split(','):
                        start, end = map(int, r.split('-'))
                        ranges.append((start-1, end))
                    
                    from PyPDF2 import PdfReader, PdfWriter
                    pdf = PdfReader(file_path)
                    
                    for i, (start, end) in enumerate(ranges):
                        writer = PdfWriter()
                        for page_num in range(start, end):
                            writer.add_page(pdf.pages[page_num])
                        
                        output_path = os.path.join(output_folder, f"split_{timestamp}_part{i+1}.pdf")
                        with open(output_path, 'wb') as output_file:
                            writer.write(output_file)
                    
                    self.status_label.config(text=f"PDF split into {len(ranges)} files in:\n{output_folder}")
                    split_dialog.destroy()
                    
                except ValueError:
                    messagebox.showerror("Error", "Invalid page range format")
                except Exception as e:
                    messagebox.showerror("Error", f"Error splitting PDF: {e}")
            
            Button(split_dialog, text="Split", command=process_split).pack(pady=10)
            Button(split_dialog, text="Cancel", command=split_dialog.destroy).pack(pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")

    def trim_audio(self):
        try:
            file_path = filedialog.askopenfilename(
                title="Select Audio File",
                filetypes=[("Audio files", "*.mp3 *.wav *.ogg *.m4a")]
            )
            if not file_path:
                return
            
            # Create themed trim dialog
            trim_dialog = Toplevel(self)
            trim_dialog.title("Trim Audio")
            trim_dialog.geometry("300x250")
            ThemeManager.apply_theme(trim_dialog, config.get("theme", "Classic"))
            
            Label(trim_dialog, text="Enter trim points (MM:SS):").pack(pady=5)
            
            time_frame = Frame(trim_dialog)
            time_frame.pack(pady=5)
            
            Label(time_frame, text="Start:").pack(side="left")
            start_var = StringVar()
            Entry(time_frame, textvariable=start_var, width=8).pack(side="left", padx=5)
            
            Label(time_frame, text="End:").pack(side="left")
            end_var = StringVar()
            Entry(time_frame, textvariable=end_var, width=8).pack(side="left", padx=5)

            def process_trim():
                try:
                    # Get the start and end times
                    start_time_str = start_var.get()
                    end_time_str = end_var.get()

                    # Convert MM:SS to total milliseconds
                    start_minutes, start_seconds = map(float, start_time_str.split(':'))
                    end_minutes, end_seconds = map(float, end_time_str.split(':'))

                    start_time = (start_minutes * 60 + start_seconds) * 1000  # Convert to milliseconds
                    end_time = (end_minutes * 60 + end_seconds) * 1000  # Convert to milliseconds
                    
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_path = os.path.join(get_trimmed_audio_folder(), 
                                             f"trimmed_{timestamp}_{os.path.basename(file_path)}")
                    
                    audio = AudioSegment.from_file(file_path)
                    trimmed_audio = audio[start_time:end_time]
                    trimmed_audio.export(output_path, format=os.path.splitext(output_path)[1][1:])
                    
                    self.status_label.config(text=f"Audio trimmed and saved!\nLocation: {output_path}")
                    trim_dialog.destroy()
                    
                except ValueError:
                    messagebox.showerror("Error", "Please enter valid time in MM:SS format")
                except Exception as e:
                    messagebox.showerror("Error", f"Error trimming audio: {e}")
            
            Button(trim_dialog, text="Trim", command=process_trim).pack(pady=10)
            Button(trim_dialog, text="Cancel", command=trim_dialog.destroy).pack(pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")

    def generate_qr(self):
        try:
            import qrcode
            
            # Create themed QR dialog
            qr_dialog = Toplevel(self)
            qr_dialog.title("Generate QR Code")
            qr_dialog.geometry("400x250")
            ThemeManager.apply_theme(qr_dialog, config.get("theme", "Classic"))
            
            Label(qr_dialog, text="Enter text/URL for QR code:").pack(pady=5)
            
            text_var = StringVar()
            Entry(qr_dialog, textvariable=text_var, width=40).pack(pady=5)
            
            # Size options
            size_frame = Frame(qr_dialog)
            size_frame.pack(pady=5)
            Label(size_frame, text="Size:").pack(side="left")
            size_var = StringVar(value="5")
            ttk.Combobox(size_frame, textvariable=size_var, values=["3", "5", "7", "10"], width=5).pack(side="left", padx=5)
            
            def generate():
                try:
                    text = text_var.get().strip()
                    if not text:
                        messagebox.showerror("Error", "Please enter text/URL")
                        return
                    
                    size = int(size_var.get())
                    
                    qr = qrcode.QRCode(version=1, box_size=size, border=5)
                    qr.add_data(text)
                    qr.make(fit=True)
                    
                    img = qr.make_image(fill_color="black", back_color="white")
                    
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_path = os.path.join(get_qr_codes_folder(), f"qr_{timestamp}.png")
                    
                    img.save(output_path)
                    self.status_label.config(text=f"QR code generated!\nLocation: {output_path}")
                    qr_dialog.destroy()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Error generating QR code: {e}")
            
            Button(qr_dialog, text="Generate", command=generate).pack(pady=10)
            Button(qr_dialog, text="Cancel", command=qr_dialog.destroy).pack(pady=5)
            
        except ImportError:
            messagebox.showerror("Error", "Please install qrcode package: pip install qrcode[pil]")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")

    def rename_files(self):
        try:
            files = filedialog.askopenfilenames(
                title="Select Files to Rename",
                filetypes=[("All files", "*.*")]
            )
            if not files:
                return
            
            # Create a dialog for new base name
            rename_dialog = Toplevel(self)
            rename_dialog.title("Rename Files")
            rename_dialog.geometry("300x150")
            ThemeManager.apply_theme(rename_dialog, config.get("theme", "Classic"))
            
            Label(rename_dialog, text="Enter base name:").pack(pady=5)
            base_name_var = StringVar()
            Entry(rename_dialog, textvariable=base_name_var, width=30).pack(pady=5)

            def process_rename():
                base_name = base_name_var.get().strip()
                if not base_name:
                    messagebox.showerror("Error", "Please enter a valid base name.")
                    return
                
                for index, file_path in enumerate(files):
                    directory, _ = os.path.split(file_path)
                    new_file_name = f"{base_name}_{index + 1}{os.path.splitext(file_path)[1]}"
                    new_file_path = os.path.join(directory, new_file_name)
                    os.rename(file_path, new_file_path)
                
                self.status_label.config(text=f"Files renamed successfully!\nBase name: {base_name}")
                rename_dialog.destroy()

            Button(rename_dialog, text="Rename", command=process_rename).pack(pady=10)
            Button(rename_dialog, text="Cancel", command=rename_dialog.destroy).pack(pady=5)

        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")


#############################################
# Tab 4: Extra Tools (OCR & Encryption)
#############################################
class ExtraToolsFrame(Frame):
    def __init__(self, parent):
        super().__init__(parent, padx=10, pady=10)
        self.selected_file = StringVar()
        self.key = None

        Label(self, text="Extra Tools", font=("Arial", 16)).pack(pady=10)

        # --------------------------------------------------
        # OCR Frame
        # --------------------------------------------------
        ocr_frame = Frame(self)
        ocr_frame.pack(pady=10, fill="x")

        Label(ocr_frame, text="OCR Text Extraction (from Image):", font=("Arial", 12)).pack(pady=5)
        Button(ocr_frame, text="Select Image", command=self.select_image).pack(pady=5)

        # Tooltip with instructions for setting the PATH
        q_label_ocr = Label(ocr_frame, text="?", fg="blue", cursor="question_arrow")
        q_label_ocr.pack(pady=5)
        Tooltip(
            q_label_ocr,
            "Requires Tesseract OCR downloaded and the PATH to be set.\n"
            "go to https://github.com/tesseract-ocr/tesseract to download"
            
        )

        self.ocr_result = Text(ocr_frame, height=5, width=60, wrap="word")
        self.ocr_result.pack(pady=5)

        btn_ocr = Frame(ocr_frame)
        btn_ocr.pack(pady=5)
        Button(btn_ocr, text="Copy OCR Text", command=self.copy_ocr_text).pack(side="left", padx=5)
        Button(btn_ocr, text="Save OCR Text", command=self.save_ocr_text).pack(side="left", padx=5)

        # --------------------------------------------------
        # Encryption Frame
        # --------------------------------------------------
        enc_frame = Frame(self)
        enc_frame.pack(pady=10, fill="x")

        Label(enc_frame, text="File Encryption/Decryption:", font=("Arial", 12)).pack(pady=5)
        Button(enc_frame, text="Select File", command=self.select_enc_file).pack(pady=5)

        btn_enc = Frame(enc_frame)
        btn_enc.pack(pady=5)
        Button(btn_enc, text="Encrypt File", command=self.encrypt_file).pack(side="left", padx=5)
        Button(btn_enc, text="Decrypt File", command=self.decrypt_file).pack(side="left", padx=5)

        self.enc_status = Label(enc_frame, text="", fg="green")
        self.enc_status.pack(pady=5)
        Button(enc_frame, text="Copy Key", command=self.copy_key).pack(pady=5)

        # Tooltip / Info for Encryption
        q_label_enc = Label(enc_frame, text="?", fg="blue", cursor="question_arrow")
        q_label_enc.pack(pady=5)
        Tooltip(
            q_label_enc,
            "Encrypt and decrypt your files.\n"
            "Make sure to set a master password to hide the encryption keys or don't (it is up to you).\n"
            "You can copy the encryption key to use it later.\n"
            "Avoid overwriting the master password multiple times, or you may encounter nested encryption issues.\n"
        )

    def select_image(self):
        file = filedialog.askopenfilename(
            title="Select an Image",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.gif")]
        )
        if file:
            self.selected_file.set(file)
            if pytesseract:
                try:
                    text = pytesseract.image_to_string(Image.open(file))
                    self.ocr_result.delete("1.0", "end")
                    self.ocr_result.insert("1.0", text)
                except Exception as e:
                    messagebox.showerror("Error", f"Error: {e}")
            else:
                messagebox.showerror("Error", "pytesseract is not installed.")

    def copy_ocr_text(self):
        text = self.ocr_result.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "OCR text copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No OCR text available.")

    def save_ocr_text(self):
        text = self.ocr_result.get("1.0", "end").strip()
        if text:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                title="Save OCR Text As"
            )
            if file_path:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(text)
                    messagebox.showinfo("Saved", f"OCR text saved to {file_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Error: {e}")
        else:
            messagebox.showwarning("Warning", "No OCR text available to save.")

    def select_enc_file(self):
        file = filedialog.askopenfilename(title="Select a File for Encryption/Decryption")
        if file:
            self.selected_file.set(file)
            self.enc_status.config(text=f"Selected: {os.path.basename(file)}")

    def generate_key(self):
        if Fernet:
            self.key = Fernet.generate_key()
            return self.key
        else:
            messagebox.showerror("Error", "cryptography is not installed.")
            return None

    def encrypt_file(self):
        file = self.selected_file.get()
        if not file:
            messagebox.showerror("Error", "Please select a file first.")
            return
        key = self.generate_key()
        if not key:
            return
        try:
            with open(file, "rb") as f:
                data = f.read()
            fernet = Fernet(key)
            encrypted = fernet.encrypt(data)

            enc_file = os.path.join(get_encryption_folder(), os.path.basename(file) + ".enc")
            with open(enc_file, "wb") as f:
                f.write(encrypted)

            # Update KEYS_JSON
            with open(KEYS_JSON, "r") as f:
                keys = json.load(f)
            keys[os.path.basename(enc_file)] = key.decode()
            with open(KEYS_JSON, "w") as f:
                json.dump(keys, f, indent=2)

            self.enc_status.config(text=f"Encrypted: {os.path.basename(enc_file)}\nKey: {key.decode()}")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")

    def decrypt_file(self):
        file = self.selected_file.get()
        if not file:
            messagebox.showerror("Error", "Please select a file first.")
            return
        key = simpledialog.askstring("Input", "Enter decryption key:")
        if not key:
            return
        try:
            with open(file, "rb") as f:
                data = f.read()
            fernet = Fernet(key.encode())
            decrypted = fernet.decrypt(data)

            dec_file = file.rsplit(".enc", 1)[0]
            with open(dec_file, "wb") as f:
                f.write(decrypted)

            self.enc_status.config(text=f"Decrypted: {os.path.basename(dec_file)}")
            if os.name == 'nt':
                os.startfile(dec_file)
            else:
                os.system(f"open {dec_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")

    def copy_key(self):
        text = self.enc_status.cget("text")
        if "Key:" in text:
            key = text.split("Key:")[-1].strip()
            if key:
                self.clipboard_clear()
                self.clipboard_append(key)
                messagebox.showinfo("Copied", "Encryption key copied to clipboard!")
            else:
                messagebox.showwarning("Warning", "No key available to copy.")
        else:
            messagebox.showwarning("Warning", "No key available to copy.")



#############################################
# Settings Window with Multiple Tabs
#############################################
class SettingsWindow(Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Settings and Help")
        self.geometry("600x500")
        self.master = master
        ThemeManager.apply_theme(master, config.get("theme", "Classic"))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # General Tab
        general_frame = Frame(notebook)
        notebook.add(general_frame, text="General")
        ThemeManager.apply_theme(general_frame, config.get("theme", "Classic"))

        # Base Folder Section
        Label(general_frame, text="Base Folder Settings", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=5)

        folder_frame = Frame(general_frame)
        folder_frame.pack(fill="x", padx=10, pady=5)

        self.base_folder = StringVar(value=get_base_folder())
        Label(folder_frame, text="Current Base Folder:").pack(anchor="w")
        Label(folder_frame, textvariable=self.base_folder, fg="blue").pack(anchor="w", padx=20)

        btn_frame = Frame(folder_frame)
        btn_frame.pack(fill="x", pady=5)
        Button(btn_frame, text="Change Base Folder", command=self.change_base_folder).pack(side="left", padx=5)
        Button(btn_frame, text="Reset to Default", command=self.reset_base_folder).pack(side="left", padx=5)

        # Master Password Section
        Label(general_frame, text="Security Settings", font=("Arial", 12, "bold")).pack(anchor="w", padx=10,
                                                                                        pady=(20, 5))

        pass_frame = Frame(general_frame)
        pass_frame.pack(fill="x", padx=10, pady=5)
        ThemeManager.apply_theme(pass_frame, config.get("theme", "Classic"))

        Label(pass_frame, text="Master Password:").pack(anchor="w")
        self.master_pass_entry = Entry(pass_frame, show="*")
        self.master_pass_entry.pack(anchor="w", padx=20, fill="x", pady=5)

        self.show_pass = BooleanVar()
        Checkbutton(pass_frame, text="Show Password", variable=self.show_pass,
                    command=self.toggle_password_visibility).pack(anchor="w", padx=20)
        

        Button(pass_frame, text="Set Master Password",
               command=self.set_master_password).pack(anchor="w", padx=20, pady=5)
        Button(pass_frame, text="Reveal Keys",
                command=self.reveal_keys).pack(anchor="w", padx=20, pady=5)

        # Appearance Tab
        appearance_frame = Frame(notebook)
        notebook.add(appearance_frame, text="Appearance")
        ThemeManager.apply_theme(appearance_frame, config.get("theme", "Classic"))

        # Screen Size Section
        Label(appearance_frame, text="Window Size", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=5)

        size_frame = Frame(appearance_frame)
        size_frame.pack(fill="x", padx=10, pady=5)

        self.screen_size = ttk.Combobox(size_frame, values=["Small", "Medium", "Large"], state="readonly")
        self.screen_size.set(config["screen_size"])
        Label(size_frame, text="Screen Size:").pack(side="left", padx=5)
        self.screen_size.pack(side="left", padx=5)

        

        # Theme Section
        Label(appearance_frame, text="Theme Settings", font=("Arial", 12, "bold")).pack(anchor="w", padx=10,
                                                                                        pady=(20, 5))

        theme_frame = Frame(appearance_frame)
        theme_frame.pack(fill="x", padx=10, pady=5)
        ThemeManager.apply_theme(theme_frame, config.get("theme", "Classic"))

        # Load custom themes before creating the combobox
        ThemeManager.load_custom_themes()

        self.theme_choice = ttk.Combobox(theme_frame, values=ThemeManager.get_theme_names(), state="readonly")
        self.theme_choice.set(config["theme"])
        Label(theme_frame, text="Theme:").pack(side="left", padx=5)
        self.theme_choice.pack(side="left", padx=5)

        # Theme management buttons
        theme_btn_frame = Frame(theme_frame)
        theme_btn_frame.pack(side="right", padx=5)

        Button(theme_btn_frame, text="Create Theme",
               command=self.create_custom_theme).pack(side="left", padx=2)
        Button(theme_btn_frame, text="Delete Theme",
               command=self.delete_custom_theme).pack(side="left", padx=2)

        # Preview Section
        Label(appearance_frame, text="Theme Preview", font=("Arial", 12, "bold")).pack(anchor="w", padx=10,
                                                                                       pady=(20, 5))

        self.preview_frame = Frame(appearance_frame, relief="solid", borderwidth=1)
        self.preview_frame.pack(fill="x", padx=10, pady=5)

        preview_content = Frame(self.preview_frame)
        preview_content.pack(padx=10, pady=10)

        Label(preview_content, text="Sample Heading", font=("Arial", 14, "bold")).pack(pady=5)
        Entry(preview_content, width=30).pack(pady=5)
        Button(preview_content, text="Sample Button").pack(pady=5)
        self.preview_progress = ttk.Progressbar(preview_content, mode='determinate', value=70)
        self.preview_progress.pack(fill='x', pady=5)

        self.theme_choice.bind("<<ComboboxSelected>>", self.preview_theme)

        Button(appearance_frame, text="Apply Theme",
               command=self.save_appearance).pack(anchor="center", pady=20)

        # Updates Tab
        updates_frame = Frame(notebook)
        notebook.add(updates_frame, text="Updates")
        ThemeManager.apply_theme(notebook, config.get("theme", "Classic"))
        ThemeManager.apply_theme(updates_frame, config.get("theme", "Classic"))
        Label(updates_frame, text="Software Updates", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        Label(updates_frame, text="Check for updates on GitHub:").pack(anchor="w", padx=10, pady=5)
        Button(updates_frame, text="Check Now", command=self.check_for_updates).pack(anchor="w", padx=20, pady=5)

    def change_base_folder(self):
        new_folder = filedialog.askdirectory(title="Select New Base Folder")
        if new_folder:
            try:
                old_base = get_base_folder()
                # Update the base folder in the user's config
                config_path = os.path.join(os.path.expanduser("~"), ".utility_app_config")
                with open(config_path, "w") as f:
                    json.dump({"base_folder": new_folder}, f)
                
                # Move the entire old base folder to the new location.
                # Note: shutil.move will remove the source folder after moving.
                import shutil
                if os.path.exists(old_base):
                    # If new_folder is not already the old base, then move
                    if os.path.abspath(new_folder) != os.path.abspath(old_base):
                        shutil.move(old_base, new_folder)
                
                self.base_folder.set(new_folder)
                messagebox.showinfo("Success", "Base folder changed successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to change base folder: {e}")

    def reset_base_folder(self):
        # Set default base folder to Documents/Complete Utility App
        default = os.path.join(os.path.expanduser("~"), "Documents", "Complete Utility App")
        try:
            # Load current base folder from config, if it exists
            config_path = os.path.join(os.path.expanduser("~"), ".utility_app_config")
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    conf = json.load(f)
                current_base = conf.get("base_folder", default)
            else:
                current_base = default

            # If the current base is different from the default, move files
            if os.path.abspath(current_base) != os.path.abspath(default):
                import shutil
                os.makedirs(default, exist_ok=True)
                for item in os.listdir(current_base):
                    src = os.path.join(current_base, item)
                    dst = os.path.join(default, item)
                    shutil.move(src, dst)
                # Optionally, remove the old base folder if it's empty
                try:
                    os.rmdir(current_base)
                except Exception as e:
                    print(f"Old base folder not empty or cannot be removed: {e}")

            # Remove the config file to reset to default settings
            if os.path.exists(config_path):
                os.remove(config_path)

            # Update the GUI reference to the base folder
            self.base_folder.set(default)
            messagebox.showinfo("Success", "Base folder reset to default!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reset base folder: {e}")


    def toggle_password_visibility(self):
        if self.show_pass.get():
            self.master_pass_entry.config(show="")
        else:
            self.master_pass_entry.config(show="*")

    def set_master_password(self):
        password = self.master_pass_entry.get().strip()
        if not password:
            messagebox.showwarning("Warning", "Please enter a valid password.")
            return

        try:
            security_manager.set_master_password(password)
            messagebox.showinfo("Success", "Master password set successfully!")
            self.master_pass_entry.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set master password: {e}")
    
    def reveal_keys(self):
        password = self.master_pass_entry.get().strip()
        if not password:
            messagebox.showwarning("Warning", "Please enter your master password.")
            return

        try:
            keys = security_manager.reveal_keys(password)
            # Instead of showing a popup, open a new screen to display keys
            self.show_keys_screen(keys)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reveal keys: {e}")

    def show_keys_screen(self, keys):
        # Create a new top-level window
        keys_window = Toplevel(self)
        keys_window.title("Revealed Keys")
        keys_window.geometry("600x500")
        
        # Create a frame for the keys text widget and scrollbar
        frame = Frame(keys_window)
        frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Create a Text widget to display keys line by line
        self.keys_text = Text(frame, wrap="word")
        self.keys_text.pack(side="left", fill="both", expand=True)
        
        # Insert keys into the text widget (each on a new line)
        self.keys_text.delete("1.0", "end")
        for key_name, key_value in keys.items():
            self.keys_text.insert("end", f"{key_name}: {key_value}\n")
        
        # Optionally disable editing so that the text is read-only
        self.keys_text.config(state="disabled")
        
        # Add a scrollbar
        scrollbar = Scrollbar(frame, command=self.keys_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.keys_text.config(yscrollcommand=scrollbar.set)
        
        btn_frame = Frame(keys_window)
        btn_frame.pack(pady=10)
        
        
        copy_btn = Button(btn_frame, text="Copy Keys", command=lambda: self.copy_keys())
        copy_btn.pack(side="left", padx=5)
        
        download_btn = Button(btn_frame, text="Download Keys", command=lambda: self.download_keys())
        download_btn.pack(side="left", padx=5)

    def copy_keys(self):
        keys = self.keys_text.get("1.0", "end").strip()
        if keys:
            self.clipboard_clear()
            self.clipboard_append(keys)
            messagebox.showinfo("Copied", "keys copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No keys available to copy.")

    def download_keys(self):
        keys = self.keys_text.get("1.0", "end").strip()
        if keys:
            default_dir = get_decrypted_key_folder()
            file_path = filedialog.asksaveasfilename(initialdir=default_dir, defaultextension=".txt",
                                                     filetypes=[("Text files", "*.txt")],
                                                     title="Save keys As")
            if file_path:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(keys)
                    messagebox.showinfo("Saved", f"keys saved to {file_path}")
                except Exception as e:
                    err = f"Error: {e}"
                    messagebox.showerror("Error", err)
        else:
            messagebox.showwarning("Warning", "No keys available to save.")


    def preview_theme(self, event=None):
        theme = self.theme_choice.get()
        ThemeManager.apply_theme(self.preview_frame, theme)


    def save_appearance(self):

        selected_size = self.screen_size.get()
        config["screen_size"] = selected_size
        config["theme"] = self.theme_choice.get()

        ThemeManager.apply_theme(self.master, config["theme"])
        save_theme_preference(config["theme"])

        if selected_size == "Small":
            self.master.geometry("700x400")
        elif selected_size == "Medium":
            self.master.geometry("840x750")
        elif selected_size == "Large":
            self.master.geometry("1024x900")

        save_screen_size_preference(selected_size)

        messagebox.showinfo("Success", "Appearance settings saved!")


    def check_for_updates(self):
        messagebox.showinfo("Updates", "No updates available. Visit our GitHub repository for the latest version.")

    def create_custom_theme(self):
        new_theme = ThemeManager.create_custom_theme(self)
        if new_theme:
            self.theme_choice['values'] = ThemeManager.get_theme_names()
            self.theme_choice.set(new_theme)
            self.preview_theme()

    def delete_custom_theme(self):
        theme = self.theme_choice.get()
        if theme in ["Classic", "Dark", "Light", "Nature", "Ocean"]:
            messagebox.showerror("Error", "Cannot delete built-in themes")
            return

        if messagebox.askyesno("Confirm Delete",
                               f"Are you sure you want to delete the theme '{theme}'?"):
            if ThemeManager.delete_custom_theme(theme):
                self.theme_choice['values'] = ThemeManager.get_theme_names()
                self.theme_choice.set("Classic")
                self.preview_theme()



#############################################
# Tab 2: Universal Tools (Same as YT Tools)
#############################################
class UniversalFrame(BaseDownloadFrame):
    def __init__(self, parent):
        super().__init__(parent, padx=10, pady=10)
        self.url_var = StringVar()
        self.download_folder = StringVar(value=get_univ_folder())

        Label(self, text="Universal Video Downloader & Transcriber (Experimental)", font=("Arial", 20)).pack(pady=10)
        Label(self, text="Enter Video URL:").pack(pady=5)
        self.url_entry = Entry(self, textvariable=self.url_var, width=60)
        self.url_entry.pack(pady=5)
        self.url_entry.bind("<Button-3>", self.show_url_context_menu)
        Button(self, text="Select Folder", command=self.select_folder).pack(pady=5)
        Label(self, textvariable=self.download_folder, fg="blue").pack(pady=5)

        Label(self, text="Select Download Type:").pack(pady=5)
        self.download_type = ttk.Combobox(self, values=["Audio Only", "Video Only", "Audio+Video"], state="readonly")
        self.download_type.set("Audio+Video")
        self.download_type.pack(pady=5)
        self.download_type.bind("<<ComboboxSelected>>", self.toggle_extra_options)

        options_frame = Frame(self)
        options_frame.pack(pady=5, fill="x")


        options_container = Frame(options_frame)
        options_container.pack(expand=True)

        options_container.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        Label(options_container, text="Select Resolution:").grid(row=0, column=0, padx=5)
        self.resolution = ttk.Combobox(options_container, values=["144p", "360p", "480p", "720p", "1080p", "4K", "8K"],
                                       state="readonly", width=15)
        self.resolution.set("1080p")
        self.resolution.grid(row=0, column=1, padx=5)

        Label(options_container, text="Select Audio Quality:").grid(row=0, column=2, padx=5)
        self.audio_quality = ttk.Combobox(options_container, values=["Auto", "128", "192", "320"],
                                          state="readonly", width=15)
        self.audio_quality.set("Auto")
        self.audio_quality.grid(row=0, column=3, padx=5)

        Label(options_container, text="Output Format:").grid(row=0, column=4, padx=5)
        self.output_format = ttk.Combobox(options_container, values=["MP4", "WEBM"],
                                          state="readonly", width=15)
        self.output_format.set("MP4")
        self.output_format.grid(row=0, column=5, padx=5)

        btn_frame = Frame(self)
        btn_frame.pack(pady=10)
        self.download_btn = Button(btn_frame, text="Download Media", command=self.download_media)
        self.download_btn.pack(side="left", padx=5)
        self.transcribe_btn = Button(btn_frame, text="Transcribe Only", command=self.transcribe_only)
        self.transcribe_btn.pack(side="left", padx=5)

        self.progress_bar = ttk.Progressbar(self, orient="horizontal", length=400, mode="determinate",
                                            style="green.Horizontal.TProgressbar")
        self.progress_bar.pack(pady=10)

        Label(self, text="Transcript Output:").pack(pady=5)
        transcript_frame = Frame(self)
        transcript_frame.pack(pady=5)
        self.transcript_text = Text(transcript_frame, height=10, width=70, wrap="word")
        self.transcript_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = Scrollbar(transcript_frame, command=self.transcript_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.transcript_text.config(yscrollcommand=scrollbar.set)

        final_btn_frame = Frame(self)
        final_btn_frame.pack(pady=10)
        Button(final_btn_frame, text="Copy Transcript", command=self.copy_transcript).pack(side="left", padx=5)
        Button(final_btn_frame, text="Download Transcript", command=self.download_transcript).pack(side="left", padx=5)

    def toggle_extra_options(self, event=None):
        mode = self.download_type.get()
        self.resolution.config(state="readonly" if mode in ["Video Only", "Audio+Video"] else "disabled")
        self.audio_quality.config(state="readonly" if mode in ["Audio Only", "Audio+Video"] else "disabled")
        self.output_format.config(state="readonly" if mode in ["Video Only", "Audio+Video"] else "disabled")

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.download_folder.set(folder)
        else:
            self.download_folder.set(get_univ_folder())

    def update_progress_bar(self, d):
        if d.get('status') == 'downloading':
            percent_str = d.get('_percent_str', '0.0%').strip()
            try:
                percent = float(percent_str.strip('%'))
            except ValueError:
                percent = 0
            self.after(0, lambda: self.progress_bar.config(value=percent))
        elif d.get('status') == 'finished':
            self.after(0, lambda: self.progress_bar.config(value=100))

    def download_media(self):
        if not self.url_var.get().strip():
            messagebox.showerror("Error", "Please enter a URL")
            return
        if not self.download_folder.get():
            self.download_folder.set(get_univ_folder())
        self.download_btn.config(state="disabled")
        self.transcribe_btn.config(state="disabled")
        threading.Thread(target=self._download_media, daemon=True).start()

    def _download_media(self):
        try:
            url = self.url_var.get().strip()
            output_path = self.download_folder.get()
            mode = self.download_type.get()
            res = self.resolution.get() if mode in ["Video Only", "Audio+Video"] else None
            aq = self.audio_quality.get() if mode in ["Audio Only", "Audio+Video"] else "Auto"
            fmt = self.output_format.get().lower() if mode in ["Video Only", "Audio+Video"] else None

            ydl_opts = {
                'outtmpl': os.path.join(output_path, '%(title)s.%(ext)s'),
                'progress_hooks': [self.update_progress_bar],
                'noplaylist': True,
                'merge_output_format': fmt if fmt in ["mp4", "webm"] else None,
                'ffmpeg_location': os.path.join(base_path, 'ffmpeg', 'bin')  # <-- Added FFmpeg location here
            }
            if mode == "Audio Only":
                pp = {"key": "FFmpegExtractAudio", "preferredcodec": "mp3"}
                if aq != "Auto":
                    pp["preferredquality"] = aq
                ydl_opts['postprocessors'] = [pp]
                ydl_opts['format'] = 'bestaudio'
            elif mode == "Video Only":
                if res:
                    h = re.sub(r'\D', '', res)
                    ydl_opts['format'] = f"bestvideo[height<={h}]"
                else:
                    ydl_opts['format'] = 'bestvideo'
            elif mode == "Audio+Video":
                if res:
                    h = re.sub(r'\D', '', res)
                    ydl_opts['format'] = f"bestvideo[height<={h}]+bestaudio"
                else:
                    ydl_opts['format'] = "bestvideo+bestaudio"
            with YoutubeDL(ydl_opts) as ydl:
                ydl.download([url])
            self.after(0, lambda: messagebox.showinfo("Success", "Download completed successfully!"))
        except Exception as e:
            err = f"Error: {e}"
            log_error(err)
            self.after(0, lambda: messagebox.showerror("Error", err))
        finally:
            self.after(0, lambda: self.download_btn.config(state="normal"))
            self.after(0, lambda: self.transcribe_btn.config(state="normal"))
            
    def transcribe_only(self):
        if not self.url_var.get().strip():
            messagebox.showerror("Error", "Please enter a URL")
            return
        if not self.download_folder.get():
            self.download_folder.set(get_univ_folder())
        self.download_btn.config(state="disabled")
        self.transcribe_btn.config(state="disabled")
        self.transcript_text.delete("1.0", "end")
        self.transcript_text.insert("1.0", "Transcribing... please wait...")
        threading.Thread(target=self._transcribe_only, daemon=True).start()

    def _transcribe_only(self):
        url = self.url_var.get().strip()
        try:
            video_id = self.extract_video_id(url)
            transcript_data = YouTubeTranscriptApi.get_transcript(video_id)
            transcript_text = "\n".join([entry["text"] for entry in transcript_data])
            self.after(0, lambda: self.transcript_text.delete("1.0", "end"))
            self.after(0, lambda: self.transcript_text.insert("1.0", transcript_text))
        except Exception as api_error:
            log_error(f"Transcript API failed: {api_error}")
            try:
                output_folder = self.download_folder.get()
                audio_path = os.path.join(output_folder, "audio_temp.mp3")
                ydl_opts = {
                    'format': 'bestaudio',
                    'postprocessors': [{"key": "FFmpegExtractAudio", "preferredcodec": "mp3"}],
                    'outtmpl': audio_path,
                    'noplaylist': True,
                }
                with YoutubeDL(ydl_opts) as ydl:
                    ydl.download([url])
                if not os.path.exists(audio_path):
                    if os.path.exists(audio_path + ".mp3"):
                        audio_path = audio_path + ".mp3"
                    else:
                        raise FileNotFoundError(f"{audio_path} not found.")
                wav_path = os.path.join(os.path.dirname(audio_path), "converted_temp.wav")
                convert_audio_to_wav(audio_path, wav_path)
                transcript = self.transcribe_audio(wav_path)
                self.after(0, lambda: self.transcript_text.delete("1.0", "end"))
                self.after(0, lambda: self.transcript_text.insert("1.0", transcript))
                if os.path.exists(audio_path):
                    os.remove(audio_path)
                if os.path.exists(wav_path):
                    os.remove(wav_path)
            except Exception as audio_error:
                err = f"Audio transcription error: {audio_error}"
                log_error(err)
                self.after(0, lambda: self.transcript_text.delete("1.0", "end"))
                self.after(0, lambda: self.transcript_text.insert("1.0", err))
        finally:
            self.after(0, lambda: self.download_btn.config(state="normal"))
            self.after(0, lambda: self.transcribe_btn.config(state="normal"))

    def copy_transcript(self):
        transcript = self.transcript_text.get("1.0", "end").strip()
        if transcript:
            self.clipboard_clear()
            self.clipboard_append(transcript)
            messagebox.showinfo("Copied", "Transcript copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No transcript available to copy.")

    def download_transcript(self):
        transcript = self.transcript_text.get("1.0", "end").strip()
        if transcript:
            default_dir = get_univ_transcription_folder()
            file_path = filedialog.asksaveasfilename(initialdir=default_dir, defaultextension=".txt",
                                                     filetypes=[("Text files", "*.txt")],
                                                     title="Save Transcript As")
            if file_path:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(transcript)
                    messagebox.showinfo("Saved", f"Transcript saved to {file_path}")
                except Exception as e:
                    err = f"Error: {e}"
                    messagebox.showerror("Error", err)
        else:
            messagebox.showwarning("Warning", "No transcript available to save.")

    def show_url_context_menu(self, event):
        context_menu = Menu(self, tearoff=0)
        context_menu.add_command(label="Paste", command=lambda: self.url_entry.event_generate("<<Paste>>"))
        context_menu.tk_popup(event.x_root, event.y_root)
        context_menu.grab_release()



#############################################
# Main Application with Menu Bar
#############################################
class CompleteApp:
    def __init__(self, root):
        self.root = root
        root.title("Complete Utility App")
        
        # Load the theme preference and screen size preference
        self.current_theme = load_theme_preference()
        config["theme"] = self.current_theme  # Update the global config
        self.screen_size = load_screen_size_preference()
        config["screen_size"] = self.screen_size  # Optionally update the config
        
        # Apply the theme immediately after loading it
        ThemeManager.apply_theme(self.root, config["theme"])

        # Update geometry based on the saved screen size
        if self.screen_size == "Small":
            self.root.geometry("700x400")
        elif self.screen_size == "Medium":
            self.root.geometry("840x750")
        elif self.screen_size == "Large":
            self.root.geometry("1024x900")
        else:
            # Fallback to a default size if needed
            self.root.geometry("840x750")
        
        # Configure grid weights for proper expansion
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)
        # Create main container frame
        self.main_frame = Frame(root)
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Create a menu bar
        self.create_menu_bar()

        # Create notebook with tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Create and add tabs
        self.yt_frame = YouTubeFrame(self.notebook)
        self.universal_frame = UniversalFrame(self.notebook)
        self.media_frame = MediaToolsFrame(self.notebook)
        self.extra_frame = ExtraToolsFrame(self.notebook)

        self.notebook.add(self.yt_frame, text="YT Tools")
        self.notebook.add(self.universal_frame, text="Universal Tools")
        self.notebook.add(self.media_frame, text="Media Tools")
        self.notebook.add(self.extra_frame, text="Extra Tools")

        # Bind resize event
        root.bind("<Configure>", self.on_window_resize)

    def create_menu_bar(self):
        menu_bar = Menu(self.root)
        self.root.config(menu=menu_bar)

        # File Menu
        file_menu = Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Download", command=self.new_download)
        file_menu.add_command(label="Open Download Folder", command=self.open_download_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Settings Menu
        settings_menu = Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Preferences", command=self.open_settings)
        settings_menu.add_separator()
        settings_menu.add_command(label="Reset All Settings", command=self.reset_settings)

        # Help Menu
        help_menu = Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.open_about)

    def apply_current_theme(self):
        ThemeManager.apply_theme(self.root, config.get("theme", "Classic"))

    def on_window_resize(self, event):
        # Only handle if it's the root window being resized
        if event.widget == self.root:
            # Update layout for better fullscreen handling
            width = event.width
            height = event.height

            # Maintain minimum size
            width = max(width, 600)
            height = max(height, 800)

            # Update notebook size and position
            self.notebook.grid_configure(padx=int(width * 0.01), pady=int(height * 0.01))

    def new_download(self):
        self.notebook.select(0)  # Switch to YT Tools tab
        # Clear any existing entries and focus on URL entry
        if hasattr(self.yt_frame, 'url_var'):
            self.yt_frame.url_var.set("")

    def open_download_folder(self):
        folder = get_base_folder()
        if os.path.exists(folder):
            if os.name == 'nt':  # Windows
                os.startfile(folder)
            else:  # macOS and Linux
                os.system(f'xdg-open "{folder}"')

    def reset_settings(self):
        if messagebox.askyesno("Reset Settings", "Are you sure you want to reset all settings to default?"):
            config["screen_size"] = "Medium"
            config["theme"] = "Classic"
            self.root.geometry("840x750")

            if os.path.exists(KEYS_JSON):
                try:
                    os.remove(KEYS_JSON)
                except Exception as e:
                    print(f"Error removing KEYS_JSON: {e}")

            security_config_path = os.path.join(get_base_folder(), "security_config.json")
            if os.path.exists(security_config_path):
                try:
                    os.remove(security_config_path)
                except Exception as e:
                    print(f"Error removing security_config.json: {e}")

            save_theme_preference("Classic")
            save_screen_size_preference("Medium")

            self.apply_current_theme()
            messagebox.showinfo("Settings Reset", "All settings have been reset to default.")


    def show_documentation(self):
        doc_window = Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("600x400")

        
        ThemeManager.apply_theme(doc_window, config.get("theme", "Classic"))

        text = Text(doc_window, wrap="word", padx=10, pady=10)
        text.pack(fill="both", expand=True)

        
        docs = """Complete Utility App – Documentation

1. Overview
Complete Utility App is a multi-purpose desktop application that bundles together various tools for downloading media,
managing files, encrypting data, converting formats, and more—all in one user-friendly interface. The app aims to simplify
your workflow by centralizing these functionalities under one roof, with customizable themes and security features.

Key Features
• YouTube Tools: Download YouTube videos (audio/video), generate transcripts, choose resolution/quality.
• Universal Tools: Download content from multiple sites, convert media, and extract audio/subtitles.
• Media Tools: Convert images to PDFs, resize images, merge/split PDFs, batch rename files.
• Extra Tools: OCR text extraction, file encryption/decryption, QR code generation, and more.
• Custom Themes: Create and manage themes to personalize the UI.
• Security: Set a master password to protect sensitive data, reveal encrypted keys, etc.

2. Getting Started
• Launch the App: Double-click the .exe (on Windows) or run from your Applications folder.
• Main Window: You’ll see a notebook (tabbed) interface:
   – YT Tools
   – Universal Tools
   – Media Tools
   – Extra Tools
• Menu Bar: Access File, Settings, and Help.
• First Steps:
   – Set a Base Folder: Under Settings > Preferences > Base Folder, choose where downloads and files will be stored.
   – Set a Master Password (optional): For encrypting/decrypting data.

3. Features & Usage

3.1 YouTube Tools
• URL Entry: Paste a YouTube URL (watch or Shorts link).
• Download Type: Choose “Audio Only,” “Video Only,” or “Audio+Video.”
• Resolution: Select from 144p up to 8K (if available).
• Audio Quality: “Auto” or specific bitrates (128, 192, 320 kbps).
• Output Format: MP4 or WEBM.
• Download: Click “Download Media” to start.
• Transcript: Use “Transcribe Only” to retrieve subtitles from YouTube’s transcript or fall back to audio-based transcription.

3.2 Universal Tools
• Similar to YT Tools but supports other sites via yt_dlp.
• Paste any supported URL, select format/resolution, then download.
• “Transcribe Only” attempts to get subtitles or auto-transcribe.

3.3 Media Tools
• Convert Images to PDF: Select images, combine into a single PDF.
• Resize Images: Bulk-resize selected images.
• Convert Image Format: JPG, PNG, BMP, GIF, WEBP, TIFF.
• Merge PDFs: Combine multiple PDF files.
• Split PDFs: Split a PDF into multiple files by page ranges.
• Batch Rename: Rename files in bulk with a chosen pattern.

3.4 Extra Tools
• OCR: Extract text from images using Tesseract (if installed).
• Encryption/Decryption: Encrypt or decrypt files with a generated key.
• QR Code Tools: Generate or scan QR codes (if included).

4. Settings & Configuration

4.1 Preferences Window
• Base Folder: Change or reset the default folder for downloads and processed files.
• Master Password: Set a password for encrypting keys and data.
• Reveal Keys: Decrypt and view your stored keys (requires Master Password).
• Window Size: Choose Small, Medium, or Large to resize the main window.
• Theme Settings: Pick from built-in themes or create your own custom theme.
• Preview: See a sample heading, button, and progress bar styled with the chosen theme.
• Apply Changes: Saves your chosen screen size and theme.

4.2 Theme Manager
• Built-in Themes: Classic, Dark, Light, Nature, Ocean, etc.
• Custom Themes: Create your own color scheme. Saved in a JSON file for future use.
• Delete Theme: Remove a custom theme you no longer need.

5. Security
• Master Password: Protects encryption keys stored in the app.
• Encryption/Decryption: When you encrypt a file, a key is generated and stored (encrypted) under the Master Password.
• Reveal Keys: Requires you to enter the Master Password again to decrypt the keys.

6. Tips & Troubleshooting
• No Sound in Downloaded Audio: Check the audio format or re-try with a different bitrate.
• OCR Not Working: Ensure Tesseract is installed or not bundled out. Check that the Tesseract path is set correctly.
• Slow Downloads: Could be your network. Try again later or switch resolution.
• Antivirus False Positives: Code is open-source; see disclaimers.
• Minimum Window Size: If you can’t shrink the window further, check if the app enforces a minimum size.

7. Legal & Ethical Considerations
• Copyright: Use this tool only to download or process media you have the right to access.
• Master Password: Keep it secure—there’s no recovery if forgotten.
• Third-Party Tools: Tools like yt_dlp are subject to their own licenses. Check those repositories for details.

8. Contact & Support
Instagram: @fissile_u235
contact: ishantstech@gmail.com
Report issues on GitHub or via email with logs/screenshots.
For more details, visit our GitHub repository.

9. License & Source Code
This project is released under the GNU General Public License (GPL). You are free to:
• Run and distribute the software.
• Modify the source code for personal or public use.
• Complete Utility App is licensed under the GNU GPL. All copies and derivative works must retain the original copyright header.
However, if you distribute modified versions, you must also release them under the GPL. For the full text, see the LICENSE file or https://www.gnu.org/licenses/gpl-3.0.en.html

10. Developer’s Note
I created Complete Utility App as a personal project to consolidate various useful utilities into one application.

About me:
• I am Ishant, I am a Class 12 student from India, I am passionate about programming and technology.
• I built this app to learn, experiment, and provide a handy toolkit for fellow enthusiasts.
• I am not responsible for how users choose to use the app—experiment responsibly.

11. Libraries used
• os – Provides functions for interacting with the operating system.
• re – Supports regular expressions for pattern matching.
• json – Handles JSON serialization and deserialization.
• threading – Enables multithreading for concurrent execution.
• hashlib – Implements hashing algorithms for secure data handling.
• base64 – Provides encoding and decoding of binary data to ASCII.
• cryptography (fernet, hazmat) – Ensures data encryption and security.
• tkinter – GUI toolkit for building user interfaces.
• img2pdf – Converts images to PDF format.
• yt_dlp – Downloads YouTube videos and extracts metadata.
• youtube_transcript_api – Retrieves YouTube video transcripts.
• speech_recognition – Converts speech to text.
• pydub – Handles audio file processing.
• PyPDF2 – Merges and manipulates PDF files.
• PIL (Pillow) – Handles image processing.
• datetime – Provides date and time functionalities.
• sys – Provides system-specific parameters and functions.

Thank you for using Complete Utility App!
"""

        text.insert("1.0", docs)
        text.config(state="disabled")

        Button(doc_window, text="Close", command=doc_window.destroy).pack(pady=10)

    def open_settings(self):
        SettingsWindow(self.root)

    def open_about(self):
        about_window = Toplevel(self.root)
        about_window.title("About")
        about_window.geometry("400x300")

        # Make the about window follow the main theme
        ThemeManager.apply_theme(about_window, config.get("theme", "Classic"))

        about_text = (
            "Complete Utility App 1.0\n\n"
            "Created by Ishant Singh\n\n"
            "Instagram: @fissile_u235\n"
            "contact: ishantstech@gmail.com\n\n"
            "This app integrates essential utilities into one secure, "
            "user-friendly platform.\n\n"
            "For more details, visit our GitHub repository."
        )

        text_widget = Text(about_window, wrap="word", padx=20, pady=20)
        text_widget.insert("1.0", about_text)
        text_widget.config(state="disabled")
        text_widget.pack(fill="both", expand=True, padx=10, pady=10)

        Button(about_window, text="Close",
               command=about_window.destroy).pack(pady=10)


if __name__ == "__main__":
    myappid = '0pen-Sourcer.utility.app.1.0'
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    root = Tk()

    ThemeManager.load_custom_themes()
    app = CompleteApp(root)

    def resource_path(relative_path):
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_path, relative_path)
    
    icon_path = resource_path("assets/icon.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)  
    else:
        print("Icon not found at:", icon_path)
    
    ThemeManager.apply_theme(root, config.get("theme", "Classic"))
    root.mainloop()
