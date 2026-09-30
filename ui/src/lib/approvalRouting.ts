import type { ApprovalPrompt } from './types';

/// Which modal an incoming approval prompt must open.
///
/// Kept as a pure function of the prompt so the routing rule is testable
/// without mounting App.svelte. A protected-system OTP arrives with no code
/// in the event (`otp_code: null`, `otp_reveal_required: true`; the code is
/// revealed by `approval_reveal_otp` behind an OS presence check — ADR-0025
/// §7.3). Routing such a prompt to the plain approval modal deadlocks it:
/// `approval_respond`/`deny` look in `pending`, while the challenge lives in
/// `otp_pending`.
export function usesOtpModal(prompt: ApprovalPrompt): boolean {
  return prompt.otp_code !== null || prompt.otp_reveal_required;
}
