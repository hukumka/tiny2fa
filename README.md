Overly simple TOTP authentication app.

### Usage

Save secret key associated with application:

```
tiny2fa --scope github init *secret key*
```

Generate code for application:

```
tiny2fa --scope github generate
```

### Builing from source

1. [Install rust toolchain)(https://rustup.rs/)

2. Clone repository and enter directory:
```
git clone https://github.com/hukumka/tiny2fa
cd tiny2fa
```

Build executable:
```
cargo build --release
```

Application will appear in `target/release`

Install executable via cargo (Optional)

```
cargo install --path .
```
