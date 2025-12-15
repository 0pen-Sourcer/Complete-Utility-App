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


from tkinter import ttk, colorchooser
import tkinter as tk
import json
import os

class ThemeManager:
    THEMES = {
        "Classic": {
            "bg": "#f0f0f0",
            "fg": "#000000",
            "button_bg": "#e0e0e0",
            "button_fg": "#000000",
            "entry_bg": "#ffffff",
            "entry_fg": "#000000",
            "accent": "#0078d7",
            "error": "#ff0000",
            "success": "#00cc00",
            "font": ("Segoe UI", 10),
            "heading_font": ("Segoe UI", 16, "bold"),
        },
        "Dark": {
            "bg": "#1e1e1e",
            "fg": "#ffffff",
            "button_bg": "#333333",
            "button_fg": "#ffffff",
            "entry_bg": "#2d2d2d",
            "entry_fg": "#ffffff",
            "accent": "#0078d7",
            "error": "#ff4444",
            "success": "#00cc00",
            "font": ("Segoe UI", 10),
            "heading_font": ("Segoe UI", 16, "bold"),
        },
        "Light": {
            "bg": "#ffffff",
            "fg": "#000000",
            "button_bg": "#f0f0f0",
            "button_fg": "#000000",
            "entry_bg": "#ffffff",
            "entry_fg": "#000000",
            "accent": "#0078d7",
            "error": "#ff0000",
            "success": "#00cc00",
            "font": ("Segoe UI", 10),
            "heading_font": ("Segoe UI", 16, "bold"),
        },
        "Nature": {
            "bg": "#f5f9f0",
            "fg": "#2c4a1d",
            "button_bg": "#a8c090",
            "button_fg": "#2c4a1d",
            "entry_bg": "#ffffff",
            "entry_fg": "#2c4a1d",
            "accent": "#4a7c3d",
            "error": "#c23b22",
            "success": "#2d5a27",
            "font": ("Segoe UI", 10),
            "heading_font": ("Segoe UI", 16, "bold"),
        },
        "Ocean": {
            "bg": "#e8f4f8",
            "fg": "#05445e",
            "button_bg": "#75e6da",
            "button_fg": "#05445e",
            "entry_bg": "#ffffff",
            "entry_fg": "#05445e",
            "accent": "#189ab4",
            "error": "#d4263e",
            "success": "#2d936c",
            "font": ("Segoe UI", 10),
            "heading_font": ("Segoe UI", 16, "bold"),
        }
    }

    CUSTOM_THEMES_FILE = os.path.join(os.path.expanduser("~"), ".utility_app_themes.json")

    @classmethod
    def load_custom_themes(cls):
        if os.path.exists(cls.CUSTOM_THEMES_FILE):
            try:
                with open(cls.CUSTOM_THEMES_FILE, 'r') as f:
                    custom_themes = json.load(f)
                cls.THEMES.update(custom_themes)
            except Exception as e:
                print(f"Error loading custom themes: {e}")

    @classmethod
    def save_custom_themes(cls):
        custom_themes = {k: v for k, v in cls.THEMES.items()
                         if k not in ["Classic", "Dark", "Light", "Nature", "Ocean"]}
        try:
            with open(cls.CUSTOM_THEMES_FILE, 'w') as f:
                json.dump(custom_themes, f, indent=2)
        except Exception as e:
            print(f"Error saving custom themes: {e}")

    @classmethod
    def create_custom_theme(cls, parent):
        theme_creator = ThemeCreator(parent)
        return theme_creator.result

    @classmethod
    def delete_custom_theme(cls, theme_name):
        if theme_name in cls.THEMES and theme_name not in ["Classic", "Dark", "Light", "Nature", "Ocean"]:
            del cls.THEMES[theme_name]
            cls.save_custom_themes()
            return True
        return False

    @classmethod
    def apply_theme(cls, root, theme_name):
        if theme_name not in cls.THEMES:
            theme_name = "Classic"
        theme = cls.THEMES[theme_name]
        style = ttk.Style()

        # Configure ttk widget styles based on theme values
        style.configure("TButton",
                        background=theme["button_bg"],
                        foreground=theme["button_fg"],
                        font=theme["font"])
        style.configure("TEntry",
                        fieldbackground=theme["entry_bg"],
                        foreground=theme["entry_fg"],
                        font=theme["font"])
        style.configure("TLabel",
                        background=theme["bg"],
                        foreground=theme["fg"],
                        font=theme["font"])
        style.configure("TFrame",
                        background=theme["bg"])
        style.configure("Heading.TLabel",
                        font=theme["heading_font"],
                        foreground=theme["fg"])
        style.configure("Success.TLabel",
                        foreground=theme["success"])
        style.configure("Error.TLabel",
                        foreground=theme["error"])
        style.configure("Accent.TButton",
                        background=theme["accent"],
                        foreground="#ffffff")
        
        # Force progress bar colors to be fixed (green for progress, fixed trough)
        style.configure("Horizontal.TProgressbar",
                        troughcolor="#e0e0e0",
                        background="green",
                        bordercolor="#e0e0e0")
        style.configure("green.Horizontal.TProgressbar",
                        troughcolor="#e0e0e0",
                        background="green",
                        bordercolor="#e0e0e0")
        style.map("Horizontal.TProgressbar",
                  background=[("active", "green"),
                              ("disabled", "#e0e0e0")],
                  troughcolor=[("active", "#e0e0e0"),
                              ("disabled", "#e0e0e0")])
        style.map("green.Horizontal.TProgressbar",
                  background=[("active", "green"),
                              ("disabled", "#e0e0e0")],
                  troughcolor=[("active", "#e0e0e0"),
                              ("disabled", "#e0e0e0")])

        # Configure the root widget background for tk widgets
        if root.winfo_class() in ("Frame", "Toplevel", "Tk"):
            try:
                root.configure(bg=theme["bg"])
            except Exception:
                pass

        # Cache theme data to avoid repeated lookups
        cached_configs = {
            "Frame": {"bg": theme["bg"]},
            "Label": {"bg": theme["bg"], "fg": theme["fg"], "font": theme["font"]},
            "Button": {
                "bg": theme["button_bg"],
                "fg": theme["button_fg"],
                "font": theme["font"],
                "activebackground": theme["accent"],
                "activeforeground": "#ffffff"
            },
            "Entry": {
                "bg": theme["entry_bg"],
                "fg": theme["entry_fg"],
                "font": theme["font"],
                "insertbackground": theme["fg"]
            },
            "Text": {
                "bg": theme["entry_bg"],
                "fg": theme["entry_fg"],
                "font": theme["font"],
                "insertbackground": theme["fg"]
            },
            "Menu": {
                "bg": theme["bg"],
                "fg": theme["fg"],
                "activebackground": theme["accent"],
                "activeforeground": "#ffffff"
            }
        }

        def configure_widget(widget):
            widget_type = widget.winfo_class()
            
            # Use cached configuration if available
            if widget_type in cached_configs:
                try:
                    widget.configure(**cached_configs[widget_type])
                except Exception:
                    pass
            elif widget_type in ("Toplevel", "Tk"):
                try:
                    widget.configure(bg=theme["bg"])
                except Exception:
                    pass
            elif widget_type == "Menubutton":
                # Menubutton uses same styling as Button
                try:
                    widget.configure(**cached_configs["Button"])
                except Exception:
                    pass

        def apply_recursive(widget):
            configure_widget(widget)
            for child in widget.winfo_children():
                apply_recursive(child)
        apply_recursive(root)

    @classmethod
    def get_theme_names(cls):
        return list(cls.THEMES.keys())

    @classmethod
    def edit_theme(cls, parent, theme_name):
        if theme_name in cls.THEMES:
            theme_editor = ThemeEditor(parent, theme_name, cls.THEMES[theme_name])
            return theme_editor.result
        return None


class ThemeCreator(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Create Custom Theme")
        self.result = None
        self.transient(parent)
        self.grab_set()
        # Removed progress bar keys so user cannot change them.
        self.elements = {
            "bg": ("Background", "#ffffff"),
            "fg": ("Text Color", "#000000"),
            "button_bg": ("Button Background", "#e0e0e0"),
            "button_fg": ("Button Text", "#000000"),
            "entry_bg": ("Entry Background", "#ffffff"),
            "entry_fg": ("Entry Text", "#000000"),
            "accent": ("Accent Color", "#0078d7"),
            "error": ("Error Color", "#ff0000"),
            "success": ("Success Color", "#00cc00")
        }
        self.colors = {}
        self.create_widgets()
        self.geometry("500x600")
        self.resizable(True, True)
        self.wait_window()

    def create_widgets(self):
        name_frame = ttk.Frame(self)
        name_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(name_frame, text="Theme Name:").pack(side="left")
        self.name_entry = ttk.Entry(name_frame)
        self.name_entry.pack(side="left", fill="x", expand=True, padx=(5, 0))
        main_container = ttk.Frame(self)
        main_container.pack(fill="both", expand=True, padx=10, pady=5)
        for key, (label, default) in self.elements.items():
            frame = ttk.Frame(main_container)
            frame.pack(fill="x", pady=5)
            ttk.Label(frame, text=label).pack(side="left")
            color_btn = tk.Button(frame, width=10, bg=default)
            color_btn.pack(side="right")
            self.colors[key] = {"button": color_btn, "value": default}
            color_btn.configure(command=lambda k=key: self.pick_color(k))
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=10, side="bottom")
        ttk.Button(btn_frame, text="Save Theme", command=self.save_theme).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side="right", padx=5)

    def pick_color(self, key):
        color = colorchooser.askcolor(self.colors[key]["value"])[1]
        if color:
            self.colors[key]["value"] = color
            self.colors[key]["button"].configure(bg=color)
            self.update_preview()

    def update_preview(self):
        theme = self.get_current_theme()
        # Optionally, update a preview widget here.
        # For now, we'll leave it empty.
        pass

    def get_current_theme(self):
        theme = {key: self.colors[key]["value"] for key in self.elements.keys()}
        theme["font"] = ("Segoe UI", 10)
        theme["heading_font"] = ("Segoe UI", 16, "bold")
        return theme

    def save_theme(self):
        name = self.name_entry.get().strip()
        if not name:
            tk.messagebox.showerror("Error", "Please enter a theme name")
            return
        if name in ThemeManager.THEMES:
            if not tk.messagebox.askyesno("Warning",
                                          f"Theme '{name}' already exists. Do you want to overwrite it?"):
                return
        ThemeManager.THEMES[name] = self.get_current_theme()
        ThemeManager.save_custom_themes()
        self.result = name
        self.destroy()


class ThemeEditor(ThemeCreator):
    def __init__(self, parent, theme_name, theme_data):
        self.theme_name = theme_name
        self.theme_data = theme_data
        self.editing = True
        self.elements = {
            "bg": ("Background", theme_data["bg"]),
            "fg": ("Text Color", theme_data["fg"]),
            "button_bg": ("Button Background", theme_data["button_bg"]),
            "button_fg": ("Button Text", theme_data["button_fg"]),
            "entry_bg": ("Entry Background", theme_data["entry_bg"]),
            "entry_fg": ("Entry Text", theme_data["entry_fg"]),
            "accent": ("Accent Color", theme_data["accent"]),
            "error": ("Error Color", theme_data["error"]),
            "success": ("Success Color", theme_data["success"])
        }
        super().__init__(parent)
        self.title(f"Edit Theme: {theme_name}")
        self.name_entry.insert(0, theme_name)
        self.name_entry.config(state="disabled" if theme_name in ["Classic", "Dark", "Light", "Nature", "Ocean"] else "normal")
        self.update_preview()

    def create_widgets(self):
        super().create_widgets()
        # Optionally, add preview widgets here.
