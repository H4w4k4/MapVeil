# <img src="logo.svg" width="28" alt=""> MapVeil

MapVeil compiles a YAML file into a **single, self-contained, password-protected
HTML file** with an interactive map. Double-click the result, enter the master
password, and browse your directory — companies, people, contacts, suppliers,
points of interest, personal address books — whatever you store in the YAML.

No server. No accounts. No plaintext on disk. The whole database is encrypted
with AES-256 and embedded inside the HTML file itself.

Try it here with password `mapveil`: [MapVeil_Directory](MapVeil_Directory.html)

## How it works

```
database.yaml ──▶ build.py ──▶ MapVeil_Directory.html (double-click to open)
                     │
                     ├─ geocodes addresses via Photon (cached in the YAML)
                     ├─ encrypts everything with AES-256 (key = SHA-256 of
                     │  your master password)
                     └─ injects the ciphertext into template.html
```

The output `MapVeil_Directory.html` is fully standalone: it decrypts in the browser,
renders a searchable directory next to a Leaflet map, and works from a local
file with no web server. Until the correct password is entered, the file
contains nothing but ciphertext.

## Features

- **Zero plaintext leakage** — build aborts if any record string is detectable
  in the output (the scan ignores the ciphertext itself and template baseline).
- **Full-text search** across every field, plus `tag:` prefix to filter by tag
  (e.g. `tag: supplier`).
- **Tag system** — filter chips with live counts, custom per-tag colors,
  chips filtered by the current search, most-frequent-first when collapsed and
  alphabetical when expanded.
- **Interactive map** — click a pin to open its popup; the sidebar list
  auto-scrolls to the matching entry. Click a card to fly to its pin.
- **Responsive** — desktop side-by-side layout, or a mobile layout
  (full-screen map + full-screen list overlay). Toggle anytime with the
  🖥/📱 button; your choice is remembered.
- **Flexible records** — a name is required; address, website, tags and any
  number of custom fields are optional. Numbers, booleans, dates, lists and
  nested objects all work.

## Requirements

- Python 3.8+
- `pip install -r requirement.txt`
  (pycryptodome, PyYAML, geopy, ruamel.yaml)

## Quick start

1. Put your data in `database.yaml` (see [Sample_Database.yaml](Sample_Database.yaml) for a complete
   example, or copy it as a starting point).
2. Run:

   ```
   python build.py
   ```

3. Set a master password when prompted (input hidden, asked twice).
4. Open the generated `MapVeil_Directory.html`, enter the password, done.

At startup the script asks whether to **reuse previously queried geocode
data** — with reuse, a rebuild takes seconds and makes no network calls.

## Editing the data

Everything lives in `database.yaml`. A record needs only a `name`; all other
fields are optional and free-form:

```yaml
- name: Jane Doe
  address: Hauptstrasse 12, 8000 Zurich, Switzerland
  website: https://example.com
  phone: "+41 79 000 00 00"
  tags: [Contact, Climbing]
  relation: friend
```

The same shape works for businesses, clubs, vacation spots, suppliers — any
entity you want to find again. Tags listed under `settings.tag_colors` get
their color in the UI.

### Positions: geocoding and manual coordinates

MapVeil resolves each record's position in this priority order:

1. **Manual `lat` / `lon`** — if a record has both, they are used *exactly* as
   given. The geocoder is never contacted for this record, and the script
   never modifies these values. Ideal for GPS fixes or records the geocoder
   can't find. Degrees are decimal; North/East are positive, South/West
   negative:

   ```yaml
   - name: Chania Office
     address: '37°01''32.9"N 25°23''25.4"E'   # free-text, shown on the card
     lat: 37.02581
     lon: 25.39039
   ```

2. **Geocode cache** — for geocoded records, the script writes `geo_lat`,
   `geo_lon` and `geo_addr` back into the YAML. The cache is reused only while
   `geo_addr` still matches the record's current `address` (editing an address
   invalidates it). These `geo_*` keys are managed by the script — leave them
   alone; they are stripped from the encrypted payload.

3. **Photon geocoding** — anything else is resolved at build time via the
   public [Photon](https://photon.komoot.io) service, rate-limited to one
   request per ~1.1 s. Unresolvable or empty addresses do not fail the build:
   the record ships as a "no map location" card.

Addresses are the only thing ever sent to the geocoder — never names or other
fields.

### YAML tips

- Quote values that YAML could misread as another type: `tags: ['5', 'yes']`.
- `lat`/`lon` (manual coordinates) must always come as a **pair**; a lone one
  aborts the build.
- Comments are preserved on rebuilds with `ruamel.yaml`.

## Security model

- AES-256-ECB with the key derived as SHA-256 of your master password — the
  browser repeats the identical derivation to decrypt. The payload is
  authenticated by structure only: a wrong password simply fails to decrypt
  into valid JSON.
- The build performs a leak scan: every record string is searched for in the
  final HTML (outside the ciphertext and template baseline), and the build
  aborts on any hit.
- `MapVeil_Directory.html` is safe to store on any cloud drive, email to yourself, or drop
  on a static host — without the password it is unreadable ciphertext.
- Only the address string is transmitted to the geocoding service at build
  time; nothing leaves your machine when the built file is used.
- Keep `database.yaml` itself private — it is, of course, plaintext.

> ⚠️ Security note: ECB mode without authentication is fine for hiding a
> directory from casual exposure (cloud backups, shared laptops), but it is
> not resistant to a determined attacker who can study the ciphertext. For
> stronger threat models use a dedicated tool (e.g. encrypted archives or
> Cryptomator) — MapVeil prioritizes the single-file, double-click experience.

## Deployment

`MapVeil_Directory.html` is a single file: send it, host it, archive it. Whatever already
has the password can be re-derived by anyone holding the file, so choose a
strong master password — the file itself provides no rate limiting on
password guesses.

## Credits & Licenses

MapVeil is released under the [MIT License](LICENSE).

- [Leaflet](https://leafletjs.com) — BSD 2-Clause
- [CryptoJS](https://github.com/brix/crypto-js) — MIT
- [Photon geocoder](https://photon.komoot.io) — openly licensed service
- Map data &copy; [OpenStreetMap](https://www.openstreetmap.org/copyright)
  contributors (ODbL)
- Esri World Street Map tiles — courtesy of
  [Esri](https://www.esri.com), used with attribution
- Python dependencies (pycryptodome, PyYAML, geopy, ruamel.yaml) — permissive
  licenses, listed in `requirement.txt`

Generated with [Lumo](https://lumo.proton.me).
