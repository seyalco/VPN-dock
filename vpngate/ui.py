"""Native GTK interface for the private VPN gateway."""

from collections import deque
from pathlib import Path
import shlex
import signal
from tempfile import TemporaryDirectory
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Adw, Gdk, GdkPixbuf, Gio, GLib, GObject, Gtk

from .core import Config, Gateway, GatewayError
from .ingress import Upstream
from .validation import NATIVE_PACKAGE_WARNING, SandboxedPackageError, validate_native

APP_ID = "io.github.vpndock.VpnDock"
STYLE = Path(__file__).with_name("style.css")
ICON = Path(__file__).with_name("vpndock.png")


def app_icon(size):
    pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(ICON), size, size, True)
    return Gtk.Image.new_from_paintable(Gdk.Texture.new_for_pixbuf(pixbuf))


def label(text, css_class=None, *, wrap=False):
    widget = Gtk.Label(label=text, xalign=0, wrap=wrap)
    if css_class:
        widget.add_css_class(css_class)
    return widget


def stack(*children, spacing=0):
    panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
    for child in children:
        panel.append(child)
    return panel


def row(*children, spacing=0):
    panel = Gtk.Box(spacing=spacing)
    for child in children:
        panel.append(child)
    return panel


def action_button(text, icon):
    return Gtk.Button(child=Adw.ButtonContent(label=text, icon_name=icon))


class Activity:
    """Collect output from workers and update GTK in bounded batches."""

    max_lines = 300

    def __init__(self):
        self.buffer = Gtk.TextBuffer()
        self.view = Gtk.TextView(
            buffer=self.buffer, editable=False, cursor_visible=False,
            monospace=True, wrap_mode=Gtk.WrapMode.CHAR,
            left_margin=10, right_margin=10, top_margin=8, bottom_margin=8,
        )
        self.scroll = Gtk.ScrolledWindow(
            child=self.view, min_content_height=148, hscrollbar_policy=Gtk.PolicyType.NEVER,
        )
        self.scroll.add_css_class("activity-console")
        self._end = self.buffer.create_mark(None, self.buffer.get_end_iter(), False)
        self._pending = deque(maxlen=self.max_lines)
        self._lock = threading.Lock()
        self._flush_source = 0

    def append(self, source, line):
        message = f"[{source}] {line.rstrip()}".replace("\r", " ").replace("\n", " ").replace("\0", "�")
        if len(message) > 2048:
            message = message[:2047] + "…"
        with self._lock:
            self._pending.append(message)
            if not self._flush_source:
                self._flush_source = GLib.timeout_add(80, self._flush)

    def _flush(self):
        with self._lock:
            batch = "\n".join(self._pending) + "\n"
            self._pending.clear()
            self._flush_source = 0
        adjustment = self.scroll.get_vadjustment()
        follow = adjustment.get_upper() - adjustment.get_page_size() - adjustment.get_value() < 12
        self.buffer.insert(self.buffer.get_end_iter(), batch)
        overflow = self.buffer.get_line_count() - self.max_lines - 1
        if overflow > 0:
            _, cutoff = self.buffer.get_iter_at_line(overflow)
            self.buffer.delete(self.buffer.get_start_iter(), cutoff)
        if follow:
            self.show_latest()
        return GLib.SOURCE_REMOVE

    def show_latest(self):
        self.view.scroll_to_mark(self._end, 0.0, True, 0.0, 1.0)


class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="VPN Dock", default_width=820, default_height=760)
        self.set_size_request(590, 505)
        self.add_css_class("vpn-dock")
        self._stop = None
        self._gateway = None
        self._closing = False
        self._confirmation = None
        self._state = None
        self._ready_once = False
        self.connect("close-request", self._close_requested)

        self.overlay = Adw.ToastOverlay()
        self.set_content(self.overlay)
        header = Adw.HeaderBar()
        header.add_css_class("dock-header")
        title = label("VPN Dock", "dock-wordmark")
        header.set_title_widget(row(app_icon(24), title, spacing=7))

        intro_title = label("VPN to local proxy", "dock-headline", wrap=True)
        intro_copy = label(
            "Start a VPN in a private network and connect apps through its loopback proxy.",
            "hero-copy", wrap=True,
        )
        intro_text = stack(intro_title, intro_copy, spacing=6)
        intro_text.set_hexpand(True)
        mark = app_icon(58)
        mark.set_valign(Gtk.Align.CENTER)
        intro = row(intro_text, mark, spacing=14)
        intro.add_css_class("dock-hero")

        self.status_dot = Gtk.Box()
        self.status_dot.set_size_request(10, 10)
        self.status_dot.set_halign(Gtk.Align.CENTER)
        self.status_dot.set_valign(Gtk.Align.CENTER)
        self.status_dot.add_css_class("status-dot")
        self.status_title = label("", "status-title")
        self.status_detail = label("", "dock-muted", wrap=True)
        status_text = stack(self.status_title, self.status_detail, spacing=4)
        status_text.set_hexpand(True)
        self.spinner = Gtk.Spinner()
        self.spinner.set_valign(Gtk.Align.CENTER)
        self.spinner.set_visible(False)
        self.state_panel = row(self.status_dot, status_text, self.spinner, spacing=13)
        self.state_panel.add_css_class("dock-card")
        self.state_panel.add_css_class("status-panel")

        self.command = Gtk.Entry(placeholder_text="Executable path with arguments", hexpand=True)
        self.command.add_css_class("dock-code")
        self.command.connect("activate", self._toggle_gateway)
        self.browse = action_button("Browse", "document-open-symbolic")
        self.browse.connect("clicked", self._browse_executable)
        self.installed = action_button("Installed apps", "view-grid-symbolic")
        self.installed.connect("clicked", self._installed_apps)
        self.terminal = action_button("Terminal command…", "utilities-terminal-symbolic")
        self.terminal.connect("clicked", self._terminal_command)
        self.folder = Gtk.Entry(placeholder_text="Working folder (defaults to home)", hexpand=True)
        self.interface = Gtk.Entry(text="auto", hexpand=True, max_length=15)
        self.interface.add_css_class("dock-code")
        self.port = Gtk.SpinButton.new_with_range(1024, 65535, 1)
        self.port.set_value(1089)
        self.port.set_numeric(True)
        self.port.set_hexpand(True)
        interface_field = stack(label("VPN interface (optional)", "field-name"), self.interface, spacing=6)
        port_field = stack(label("Local port", "field-name"), self.port, spacing=6)
        self.upstream = Gtk.Entry(placeholder_text="socks5://127.0.0.1:8083", hexpand=True)
        self.upstream.add_css_class("dock-code")
        upstream_field = stack(
            label("Upstream SOCKS5 (optional)", "field-name"),
            self.upstream, label("Leave empty for direct access. A SOCKS5 uplink carries TCP and DNS.",
                                 "dock-muted", wrap=True), spacing=6,
        )
        client_title = label("VPN client", "section-title")
        client_title.set_hexpand(True)
        compatibility = action_button("Compatibility", "help-browser-symbolic")
        compatibility.connect("clicked", self._compatibility)
        config = stack(
            row(client_title, compatibility, spacing=8), self.command,
            row(self.installed, self.browse, self.terminal, spacing=8), self.folder,
            row(interface_field, port_field, spacing=12), upstream_field, spacing=10,
        )
        self.config = config
        config.add_css_class("dock-card")

        self.endpoints = {}
        endpoint_rows = [
            self._endpoint_row("SOCKS5", "socks5"),
            self._endpoint_row("HTTP CONNECT", "http"),
        ]
        endpoints = stack(label("Local proxy addresses", "section-title"), *endpoint_rows, spacing=8)
        endpoints.add_css_class("dock-card")
        self.port.connect("value-changed", self._update_addresses)
        self._update_addresses()

        self.activity = Activity()
        self.activity_row = Adw.ExpanderRow(title="Activity log", subtitle="VPN and proxy messages")
        self.activity_row.add_row(self.activity.scroll)
        self.activity_row.connect("notify::expanded", self._activity_expanded)
        activity_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        activity_list.add_css_class("boxed-list")
        activity_list.add_css_class("activity-list")
        activity_list.append(self.activity_row)

        content = stack(intro, self.state_panel, config, endpoints, activity_list, spacing=12)
        content.add_css_class("dock-content")
        clamp = Adw.Clamp(maximum_size=800, tightening_threshold=740, child=content)
        scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True, child=clamp)

        self.start_button = action_button("Start", "media-playback-start-symbolic")
        self.start_button.add_css_class("dock-start")
        self.start_button.add_css_class("suggested-action")
        self.start_button.connect("clicked", self._toggle_gateway)
        footer = row(Gtk.Box(hexpand=True), self.start_button)
        footer.add_css_class("dock-footer")
        self.overlay.set_child(stack(header, scroll, footer))
        self._set_status("idle", "Idle", "Choose a VPN executable to start.")

    def _endpoint_row(self, title, scheme):
        address = label("", "endpoint-address", wrap=True)
        address.set_selectable(True)
        self.endpoints[scheme] = address
        copy = action_button("Copy", "edit-copy-symbolic")
        copy.set_tooltip_text(f"Copy {title} proxy address")
        copy.set_valign(Gtk.Align.CENTER)
        copy.connect("clicked", self._copy_endpoint, scheme, title)
        details = stack(label(title, "endpoint-name"), address, spacing=4)
        details.set_hexpand(True)
        item = row(details, copy, spacing=12)
        item.add_css_class("endpoint-card")
        return item

    def _update_addresses(self, *_):
        port = self.port.get_value_as_int()
        for scheme, address in self.endpoints.items():
            address.set_text(f"{scheme}://127.0.0.1:{port}")

    def _copy_endpoint(self, button, scheme, title):
        address = self.endpoints[scheme].get_text()
        button.get_clipboard().set(GObject.Value(str, address))
        self.overlay.add_toast(Adw.Toast(title=f"{title} address copied."))

    def _compatibility(self, *_):
        dialog = Adw.MessageDialog(
            transient_for=self, heading="VPN client compatibility",
            body="Choose a native executable that creates a TUN or WireGuard interface or uses the private "
                 "NetworkManager. A terminal client must stay in the foreground and be able to authenticate "
                 "without an interactive prompt.\n\n"
                 "The local SOCKS5 and HTTP CONNECT addresses accept IPv4 TCP. With an upstream SOCKS5 "
                 "proxy, the VPN transport itself must use IPv4 TCP.\n\n"
                 f"{NATIVE_PACKAGE_WARNING}",
        )
        dialog.add_response("close", "Close")
        dialog.set_close_response("close")
        dialog.present()

    def _show_package_warning(self, error):
        self._set_status("error", "Choose a native VPN client", str(error))
        dialog = Adw.MessageDialog(
            transient_for=self, heading="Choose a native VPN client", body=str(error),
        )
        dialog.add_response("close", "Close")
        dialog.set_close_response("close")
        dialog.present()

    def _save_client(self, command, folder):
        self.command.set_text(command)
        self.folder.set_text(folder)
        if self._state == "error":
            self._set_status("idle", "Idle", "VPN client selected. Start when ready.")

    def _apply_client(self, command, folder):
        try:
            Config(command, "auto", 1089, folder).argv()
        except SandboxedPackageError as error:
            self._show_package_warning(error)
        except (GatewayError, ValueError, OSError) as error:
            self._set_status("error", "Cannot use this launcher", str(error))
        else:
            self._save_client(command, folder)

    def _apply_desktop(self, app):
        try:
            validate_native((), desktop=app)
            raw = app.get_string("Exec") or ""
            args = [arg.replace("%%", "%") for arg in shlex.split(raw)
                    if not arg.startswith("%") and arg not in ("@@", "@@u")]
            directory = app.get_string("Path") or ""
            command = shlex.join(args)
            Config(command, "auto", 1089, directory).argv()
            if app.get_boolean("Terminal"):
                raise GatewayError("This launcher needs an interactive terminal.")
        except SandboxedPackageError as error:
            self._show_package_warning(error)
        except (GatewayError, ValueError, OSError) as error:
            self._set_status("error", "Cannot use this launcher", str(error))
        else:
            self._save_client(command, directory)

    def _browse_executable(self, *_):
        dialog = Gtk.FileChooserNative(
            title="Choose VPN executable", transient_for=self,
            action=Gtk.FileChooserAction.OPEN, accept_label="Choose", cancel_label="Cancel",
        )

        def response(chooser, result):
            file = chooser.get_file() if result == Gtk.ResponseType.ACCEPT else None
            chooser.destroy()
            if file is None or not (filename := file.get_path()):
                return
            path = Path(filename)
            if path.suffix == ".desktop" and (app := Gio.DesktopAppInfo.new_from_filename(filename)):
                self._apply_desktop(app)
            else:
                self._apply_client(shlex.quote(filename), str(path.parent))

        dialog.connect("response", response)
        dialog.show()

    def _terminal_command(self, *_):
        dialog = Adw.MessageDialog(transient_for=self, heading="Terminal command",
                                   body="Enter an executable and arguments, and the folder to run it in.")
        command = Gtk.Entry(text=self.command.get_text(), placeholder_text="./myapp --config profile.conf")
        folder = Gtk.Entry(text=self.folder.get_text() or str(Path.home()), placeholder_text="Working folder")
        dialog.set_extra_child(stack(command, folder, spacing=8))
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("use", "Use command")
        dialog.set_default_response("use")
        command.set_activates_default(True)

        def respond(_, response):
            if response == "use":
                self._apply_client(command.get_text(), folder.get_text())

        dialog.connect("response", respond)
        dialog.present()

    def _installed_apps(self, *_):
        dialog = Gtk.Window(title="Installed applications", transient_for=self, modal=True,
                            default_width=500, default_height=480)
        search = Gtk.SearchEntry(placeholder_text="Find an application")
        listing = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        listing.add_css_class("boxed-list")
        dialog.set_child(stack(search, Gtk.ScrolledWindow(child=listing, vexpand=True), spacing=8))
        available = sorted((app for app in Gio.AppInfo.get_all()
                            if isinstance(app, Gio.DesktopAppInfo) and app.should_show()),
                           key=lambda app: app.get_display_name().casefold())

        def choose(_, app):
            dialog.close()
            self._apply_desktop(app)

        def rebuild(*_):
            while child := listing.get_first_child():
                listing.remove(child)
            query = search.get_text().casefold()
            for app in available:
                if query in app.get_display_name().casefold():
                    item = Adw.ActionRow(title=GLib.markup_escape_text(app.get_display_name()), activatable=True)
                    item.connect("activated", choose, app)
                    listing.append(item)

        search.connect("search-changed", rebuild)
        rebuild()
        dialog.present()

    def _activity_expanded(self, row_widget, _):
        if row_widget.get_expanded():
            self.activity.show_latest()

    def _set_status(self, state, title, detail):
        if self._state:
            self.state_panel.remove_css_class(self._state)
        self._state = state
        self.state_panel.add_css_class(state)
        self.status_title.set_text(title)
        self.status_detail.set_text(detail)
        busy = state in {"waiting", "stopping"}
        self.spinner.set_spinning(busy)
        self.spinner.set_visible(busy)

    def _toggle_gateway(self, *_):
        if self._stop is not None:
            self._request_stop()
            return
        try:
            command = self.command.get_text().strip()
            if not command:
                self.command.grab_focus()
                raise GatewayError("Choose the VPN executable or enter its command.")
            config = Config(
                command=command, interface=self.interface.get_text().strip() or "auto",
                port=self.port.get_value_as_int(), directory=self.folder.get_text(),
                upstream=self.upstream.get_text().strip(),
            )
            config.argv()
            Upstream.parse(config.upstream)
        except SandboxedPackageError as error:
            self._show_package_warning(error)
            return
        except (GatewayError, ValueError, OSError) as error:
            self._set_status("error", "Check settings", str(error))
            return
        self._ready_once = False
        waiting = ("Waiting for a VPN interface or a client-owned local proxy." if config.interface == "auto"
                   else f"Waiting for the VPN to bring up {config.interface}.")
        stop = threading.Event()
        self._stop = stop
        self._set_running(True)
        self._set_status("waiting", "Waiting", waiting)
        self.activity.append("VPN Dock", "Starting the VPN client in a private session.")

        def run():
            error = None
            try:
                with Gateway(config, output=self.activity.append) as gateway:
                    GLib.idle_add(self._attach_gateway, stop, gateway)
                    gateway.start(stop)
                    gateway.follow(stop)
            except Exception as exception:
                if not stop.is_set():
                    error = str(exception) or type(exception).__name__
                    self.activity.append("VPN Dock", error)
            GLib.idle_add(self._finished, stop, error)

        threading.Thread(target=run, name="vpn-dock-session", daemon=True).start()
        GLib.timeout_add(180, self._refresh_gateway, stop, waiting)

    def _attach_gateway(self, stop, gateway):
        if self._stop is stop:
            self._gateway = gateway
        return GLib.SOURCE_REMOVE

    def _refresh_gateway(self, stop, waiting):
        if self._stop is not stop:
            return GLib.SOURCE_REMOVE
        if stop.is_set():
            return GLib.SOURCE_CONTINUE
        ready = self._gateway is not None and self._gateway.ready.is_set()
        if ready and self._state != "ready":
            self._ready_once = True
            self._set_status(
                "ready", "Ready",
                "The selected forwarding path is ready. Check Internet access from the app using this proxy.",
            )
        elif not ready and self._state == "ready":
            self._set_status("waiting", "VPN disconnected", waiting)
        return GLib.SOURCE_CONTINUE

    def _set_running(self, running):
        self.config.set_sensitive(not running)
        content = self.start_button.get_child()
        self.start_button.set_sensitive(True)
        content.set_label("Stop" if running else "Start")
        content.set_icon_name("media-playback-stop-symbolic" if running else "media-playback-start-symbolic")
        if running:
            self.start_button.remove_css_class("suggested-action")
        else:
            self.start_button.add_css_class("suggested-action")

    def _request_stop(self):
        if self._stop is None or self._stop.is_set():
            return
        self._stop.set()
        self.start_button.set_sensitive(False)
        self._set_status("stopping", "Stopping", "Closing the VPN and its local proxy.")

    def _finished(self, stop, error):
        if self._stop is not stop:
            return GLib.SOURCE_REMOVE
        self._stop = None
        self._gateway = None
        if self._closing:
            self.destroy()
            return GLib.SOURCE_REMOVE
        self._set_running(False)
        if error and not stop.is_set():
            title = "VPN disconnected" if self._ready_once else "VPN session failed"
            self._set_status("error", title, error)
            self.activity_row.set_expanded(True)
        else:
            self._set_status("idle", "Stopped", "The VPN command and local proxy have stopped.")
        return GLib.SOURCE_REMOVE

    def _close_requested(self, *_):
        if self._stop is None:
            return False
        if self._closing or self._stop.is_set():
            self._closing = True
            return True
        if self._confirmation is not None:
            self._confirmation.present()
            return True
        dialog = Adw.MessageDialog(
            transient_for=self, heading="Stop VPN Dock?",
            body="Closing the window ends the VPN session and its local proxy.",
        )
        dialog.add_response("cancel", "Keep running")
        dialog.add_response("stop", "Stop and close")
        dialog.set_response_appearance("stop", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def respond(_, response):
            self._confirmation = None
            if response == "stop":
                self.shutdown()

        self._confirmation = dialog
        dialog.connect("response", respond)
        dialog.present()
        return True

    def shutdown(self):
        if self._stop is None:
            self.destroy()
        else:
            self._closing = True
            self._request_stop()


class Application(Adw.Application):
    def __init__(self):
        GLib.set_prgname(APP_ID)
        GLib.set_application_name("VPN Dock")
        super().__init__(application_id=APP_ID)
        self._fallback_icons = None

    def do_startup(self):
        Adw.Application.do_startup(self)
        display = Gdk.Display.get_default()
        provider = Gtk.CssProvider()
        provider.load_from_path(str(STYLE))
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )
        icons = Gtk.IconTheme.get_for_display(display)
        if not icons.has_icon(APP_ID):
            self._fallback_icons = TemporaryDirectory(prefix="vpndock-icon-")
            folder = Path(self._fallback_icons.name)
            (folder / f"{APP_ID}.png").symlink_to(ICON.resolve())
            icons.add_search_path(str(folder))
        Gtk.Window.set_default_icon_name(APP_ID)
        for watched_signal in (signal.SIGINT, signal.SIGTERM):
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, watched_signal, self._shutdown)

    def do_shutdown(self):
        if self._fallback_icons is not None:
            self._fallback_icons.cleanup()
        Adw.Application.do_shutdown(self)

    def do_activate(self):
        window = self.get_active_window() or Window(self)
        window.present()

    def _shutdown(self):
        for window in self.get_windows():
            if isinstance(window, Window):
                window.shutdown()
                break
        else:
            self.quit()
        return GLib.SOURCE_CONTINUE
