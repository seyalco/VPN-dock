# VPN Dock

VPN Dock runs a trusted Linux VPN client in private user, network, mount and PID
namespaces with a private NetworkManager and system and session D-Bus. It exposes
the selected VPN path as SOCKS5 and HTTP CONNECT on `127.0.0.1`.

## Use the application

1. Open the Linux x86-64 portable executable or run `./run-vpndock` from source.
2. Select the client with **Installed apps**, **Browse**, or **Terminal
   command…**. Terminal commands can take arguments and a working folder.
3. Leave **Upstream SOCKS5** empty for direct access or enter Proxy A, for example
   `socks5://127.0.0.3:2080`. A configured SOCKS5 uplink carries IPv4 TCP and DNS.
4. Select **Start** and connect in the VPN client. After **Ready**, set the
   downstream app to `socks5://127.0.0.1:1089` or `http://127.0.0.1:1089`.
   Substitute your chosen local port.
5. **Stop** ends the private session. When a selected tunnel route or local
   listener disappears, VPN Dock stops forwarding and checks for a new path.

Both output protocols share one local port and carry IPv4 TCP. SOCKS5 declines
UDP ASSOCIATE. Local processes on the host can use the listener.

The Linux x86-64 release executable includes sing-box 1.14.4. The desktop and
Linux dependencies below still apply. Mark the downloaded file as runnable
if needed and launch it directly.

```sh
chmod +x VPN-Dock-0.7.1-linux-x86_64
./VPN-Dock-0.7.1-linux-x86_64
```

From the extracted source package, run
`./packaging/register-desktop.sh /absolute/path/to/VPN-Dock` to register the
executable and its icon in your application menu. Keep the executable at a
stable path. VPN Dock follows the desktop’s light or dark appearance setting.

## Compatibility and requirements

Select an executable from an installed native `.rpm` or `.deb` package,
commonly under `/usr/bin` or `/opt`, or choose a standalone Linux executable.
The **Compatibility & Requirements** dialog explains supported launches.
Flatpak, Snap, browser extensions and X11-only GUI clients are unsupported.
Use a TCP-based VPN transport through a TCP-only relay such as SOCKS5 or HTTP
CONNECT. The upstream field in VPN Dock accepts SOCKS5.

A native Wayland client can use the private NetworkManager, an IPv4 route
through a TUN, TAP or WireGuard interface, or an application-owned IPv4
loopback SOCKS5 or HTTP CONNECT listener. Compatible CLI clients work without
a display. Clients with companion daemons can use a foreground launch script
that starts both programs inside the private session.

Install `gnome-keyring` for applications that use Secret Service. VPN Dock
starts and unlocks a separate keyring for each selected executable. Its data
and generated unlock record are stored in owner-only directories under
`${XDG_CONFIG_HOME:-$HOME/.config}/vpndock/keyrings`. The application sees its
private store. The unlock record is supplied to the daemon through a pipe.
GSettings uses a private dconf writer and user profile when dconf is installed.
Other desktop settings and application state start fresh each session.

## Network boundaries

- Direct mode uses pasta's user-space network translation. SOCKS5 upstream
  mode uses a private TUN and a Unix-socket relay to A. Bootstrap DNS uses
  DNS-over-HTTPS through A. Use direct mode for UDP-only VPN transports.
- The downstream proxy has its own delegated Linux UID. Private nftables
  permits IPv4 TCP through the selected VPN interface or to the exact client
  loopback endpoint, plus replies to the local relay. It blocks fallback to
  both base interfaces. Interface mode also binds destination traffic and
  DoH to the selected VPN interface.
- Keep **VPN interface** on `auto` to detect local proxies. VPN Dock first
  checks the normal IPv4 route for a tunnel. It then checks verified listeners
  owned by the application before trying an interface-bound policy route.
  If multiple supported listeners are present, a matching private GSettings
  proxy setting can identify the intended one. Local SOCKS5 and HTTP CONNECT
  detection expects no authentication. HTTP detection uses a loopback CONNECT
  challenge.
- **Ready** identifies a usable forwarding path. In local-proxy mode the
  client controls its own connection and traffic policy, including what it
  does while disconnected. Check public exit from a downstream app.
- The selected client's network privileges apply inside its private
  namespaces. Use trusted executables.

## Dependencies and verification

Linux needs enabled unprivileged user namespaces and delegated UID and GID
ranges for the desktop user. On Fedora the runtime uses Python 3, PyGObject,
GTK 4, libadwaita, NetworkManager, dbus-daemon, bubblewrap, util-linux,
shadow-utils-subid, iproute, nftables, passt/pasta, socat and `/dev/net/tun`.
Use dconf and GNOME Keyring for private desktop settings and Secret Service.

For source runs, install sing-box 1.14 or later using the [upstream package instructions](https://sing-box.sagernet.org/installation/package-manager/) or extract the executable for your architecture from an [official sing-box release](https://github.com/SagerNet/sing-box/releases). From the extracted directory, use `install -Dm755 ./sing-box "$HOME/.local/bin/sing-box"`.

The published portable uses its embedded copy. Source runs and portable builds without an embedded engine check the following locations in order.

1. The explicit `VPNDOCK_SING_BOX` override, when set.
2. `bin/sing-box` beside the launcher, followed by `sing-box` in the same directory. For a source run, these paths are relative to the checkout.
3. `${XDG_DATA_HOME:-$HOME/.local/share}/vpndock/bin/sing-box`, then `~/.local/bin/sing-box`.
4. `sing-box` on `$PATH`.

Run `./run-vpndock --check-runtime` to check the setup.

```sh
VPNDOCK_SING_BOX=/path/to/sing-box /usr/bin/python3 tests/integration.py
./packaging/make-portable.sh /tmp/VPN-Dock-0.7.1-linux-x86_64
./packaging/make-release.sh /tmp
```

The example above builds a portable that uses an external engine. To include your own engine, pass `--engine FILE --engine-license FILE --engine-source HTTPS_URL` before the output path. The builder writes a companion SHA-256 file.

The Linux test exercises direct mode and a controlled SOCKS5 A, a real TUN and
client-owned HTTP and SOCKS listeners, both downstream protocols, kernel
fallback blocking, and reconnect. It checks that the host IPv4 route table
stays the same. To test Tundock as a downstream consumer, set
`VPNDOCK_TEST_TUNDOCK_SOURCE=/path/to/tundock`.

## License

VPN Dock is licensed under GPL-3.0-or-later. The portable includes sing-box by SagerNet, licensed under GPL-3.0-or-later with the additional terms in its upstream license notice. Run the portable with `--portable-notices` to see the licenses and link to the matching engine source. [VPN Dock license](LICENSE) · [Third-party notices](THIRD-PARTY-NOTICES) · [Release downloads and corresponding source](https://github.com/seyalco/VPN-dock/releases)
