export interface AppStatus {
  csrf_token: string;
  vnc_authenticated: boolean;
  settings_authenticated: boolean;
  vnc_password_enabled: boolean;
  settings_password_enabled: boolean;
  engine_connected?: boolean;
  control_connected?: boolean;
  native_qr_mode?: boolean;
  mode_switching?: boolean;
  mode_error?: string | null;
  engine_message?: string;
}
export interface Credential {
  credential_id: string;
  rp_id?: string | null;
  user_handle?: string | null;
  user_name?: string | null;
  user_display_name?: string | null;
  registered_at?: number | null;
  sign_count?: number | null;
  resident?: boolean | null;
  registration_identity?: unknown;
  registration_aaguid?: string | null;
  registration_attestation?: string | null;
  registration_requested_attestation?: string | null;
}
export interface VirtualKey {
  id: string;
  name: string;
  attachment: string;
  enabled: boolean;
  provider_label?: string;
  provider?: string;
  model_aaguid?: string;
  aaguid?: string;
  presence_timeout_seconds?: number;
  resident_key_supported?: boolean;
  attestation_mode?: string;
  pin_configured?: boolean;
  credentials: Credential[];
  attestation_certificate?: {
    subject: string;
    not_before: string;
    not_after: string;
    sha256: string;
    chain_length: number;
    currently_valid: boolean;
    registration_usable: boolean;
    warning?: string;
    trust?: string;
  } | null;
}
export interface RuntimeStatus {
  state: string;
  message?: string;
  sandbox_enabled?: boolean;
  [key: string]: unknown;
}
