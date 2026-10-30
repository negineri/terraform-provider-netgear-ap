# terraform-provider-netgear-ap

NETGEAR WAX210 (AX1800 WiFi 6 Dual Band PoE Access Point) をスタンドアロンモードで管理する Terraform Provider です。
[terraform-plugin-framework](https://github.com/hashicorp/terraform-plugin-framework) で実装しています。

WAX210 には REST API がないため、この Provider は Web UI (LuCI) がブラウザ上で行う操作 (ログイン、CBI フォームの POST、UCI 変更の Apply) をエミュレートします。

動作確認済み: WAX210 firmware V1.1.0.31

## 機能

| 種類 | 名前 | 内容 |
| --- | --- | --- |
| Resource | `netgear_ssid` | SSID スロット 1-4 (2.4GHz/5GHz 共通) の SSID 名、バンド別有効化、セキュリティ (None / OWE / WPA2・WPA3 Personal / WPA2・WPA3 Enterprise)、パスフレーズ、ステルス、クライアント分離、VLAN、Fast Roaming、バンドステアリング、RADIUS 認証・アカウンティング、MAC フィルタ |
| Resource | `netgear_radio` | 2.4GHz / 5GHz 無線の Wireless Mode、チャンネル、チャンネル幅、送信出力、RTS しきい値、クライアント数制限、Green Mode、Aggregation (2.4GHz のみ) |
| Data Source | `netgear_device` | モデル名、AP 名、シリアル番号、ファームウェアバージョン、MAC アドレス、国、管理 IP など |

詳細は [docs/](docs/) を参照してください。

## 使い方

```hcl
terraform {
  required_providers {
    netgear = {
      source = "negineri/netgear-ap"
    }
  }
}

provider "netgear" {
  endpoint = "https://192.168.0.100"
  # password は NETGEAR_AP_PASSWORD 環境変数でも指定可能
}

resource "netgear_ssid" "office" {
  slot          = 1
  ssid          = "office"
  passphrase    = var.office_passphrase
  band_steering = true
}

resource "netgear_radio" "radio_5g" {
  band    = "5GHz"
  channel = "36"
}
```

Provider の Type 名は `netgear` なので、`required_providers` のローカル名も `netgear` にしてください。

Provider の設定値は環境変数でも指定できます。

| 属性 | 環境変数 | 既定値 |
| --- | --- | --- |
| `endpoint` | `NETGEAR_AP_ENDPOINT` | なし (必須) |
| `username` | `NETGEAR_AP_USERNAME` | `admin` |
| `password` | `NETGEAR_AP_PASSWORD` | なし (必須) |
| `insecure` | `NETGEAR_AP_INSECURE` | `true` (自己署名証明書のため) |
| `apply_timeout` | - | `180` 秒 |

## 注意事項

- **ログインセッションは 1 つだけ**: WAX210 は同時に 1 セッションしかログインできません。Terraform を実行すると Web UI にログイン中のユーザーはログアウトされます (逆も同様)。
- **未適用の変更がある場合は失敗します**: Web UI で保存したまま Apply していない変更 (staged changes) があると、それも一緒に Apply してしまうため、Provider はエラーで停止します。Web UI で Apply か Revert をしてから実行してください。
- **ログイン失敗によるロック**: パスワードを誤ると、デバイスのブルートフォース対策でしばらくログインできなくなります。
- **SSID スロットは常に存在します**: `netgear_ssid` の作成はスロットの設定の上書き、削除は両バンドでの無効化です (その他の設定は残ります)。
- **`netgear_radio` は指定した属性だけを管理します**: 未指定の属性はデバイスの現在値を保持します。削除してもデバイスの設定は変更されません。
- パスフレーズや RADIUS シークレットは Web UI 内蔵の固定キーで AES 暗号化されてやり取りされます (Web UI と同じ方式で、実質的な保護にはなりません)。HTTPS で接続してください。state にも平文で保存されるため、state の取り扱いに注意してください。
- Enterprise 以外のセキュリティモードでは RADIUS 認証サーバーとシークレットを、`accounting_enabled = false` ではアカウンティングサーバーとシークレットをデバイスから消去します。
- PMF (802.11w) などはセキュリティモードに応じてデバイスが自動設定します。
- 未対応: ゲストネットワーク (キャプティブポータル)、管理 VLAN、管理 SSID、IP 設定、WDS/メッシュ、スケジューラ、ファームウェア更新など。

## 開発

```sh
make build     # ビルド
make test      # ユニットテスト
make docs      # docs/ の再生成 (tfplugindocs)
```

### 受け入れテスト

受け入れテストは実機に対して実行し、**SSID スロット 4 と 2.4GHz 無線の RTS しきい値を変更します**。どちらもテスト終了時に元の値へ戻しますが、テストが途中で中断された場合は戻らないことがあります。テスト専用の AP で実行してください。

```sh
export NETGEAR_AP_ENDPOINT=https://192.168.0.100
export NETGEAR_AP_PASSWORD=...
make testacc
```

[mise](https://mise.jdx.dev/) を使う場合は、`mise.local.toml` (`.gitignore` で除外済み) に環境変数を書いておけます。

```toml
[env]
NETGEAR_AP_ENDPOINT = "https://192.168.0.100"
NETGEAR_AP_PASSWORD = "..."
```

### ローカルでの動作確認

`~/.terraformrc` に `dev_overrides` を設定すると、ビルドしたバイナリを直接使えます。

```hcl
provider_installation {
  dev_overrides {
    "negineri/netgear-ap" = "/path/to/terraform-provider-netgear-ap"
  }
  direct {}
}
```

## 実装メモ

| 処理 | エンドポイント |
| --- | --- |
| ログイン | `POST /cgi-bin/luci` (`password` は `sha512(password + "\n")`、`Origin`/`Referer` ヘッダ必須) |
| CSRF トークン | `admin/system/ajax_getCsrf` → `admin/system/ajax_setCsrf` |
| SSID の読み取り | `admin/network/iface_status2/99,app,guest,lan,mgmt` (各 wifi-iface の UCI 値を JSON で取得) |
| SSID の書き込み | `admin/network/wifi_Encryption_P2P` のフォームを取得し、ブラウザの JavaScript と同じ加工をして `admin/network/wireless_device` に POST |
| 無線の読み書き | `admin/network/wifi_device?device=wifi0` / `wifi1` と `admin/network/wireless_device` のフォーム |
| 有効な SSID 数 | SSID・無線の書き込み時に `cbid.wireless.wifiN.ath_count` (バンドごとの有効な SSID 数) を送信 (Web UI の Save と同じ) |
| 適用 | `admin/uci/saveapply` で UCI をコミットし、その応答ページの JavaScript と同じく `servicectl/restart/<configs>` でサービスを再起動、`servicectl/status` が `finish` になるまで待機。その後 `admin/system/ajax_get_reload_state` と `admin/uci/changes` で完了を確認 |
