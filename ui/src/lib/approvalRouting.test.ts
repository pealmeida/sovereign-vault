import { describe, expect, it } from 'vitest';

import type { ApprovalPrompt } from './types';
import { usesOtpModal } from './approvalRouting';

/// Routing guard for the OTP reveal bug (ADR-0025 §7.3).
///
/// On a protected system the backend sends `otp_code: null` together with
/// `otp_reveal_required: true`. The old App.svelte condition routed by
/// `otp_code !== null` alone, so the challenge fell into ApprovalModal,
/// whose Approve/X call `approval_respond`/`deny` against `pending` while
/// the challenge lives in `otp_pending` — "unknown approval request" and a
/// dead card. These tests pin the correct surface choice.

function prompt(overrides: Partial<ApprovalPrompt> = {}): ApprovalPrompt {
  return {
    id: 7,
    action: 'ReadFile',
    container: 'notes',
    file_name: 'a.txt',
    mode: 'OTP',
    byte_size: null,
    otp_code: null,
    protected: true,
    otp_reveal_required: false,
    pre_unlock: false,
    ...overrides,
  };
}

describe('usesOtpModal', () => {
  it('routes a declared-system OTP (code in the event) to the OTP modal', () => {
    expect(usesOtpModal(prompt({ otp_code: '246810' }))).toBe(true);
  });

  it('routes a protected OTP (null code, reveal required) to the OTP modal', () => {
    expect(
      usesOtpModal(prompt({ otp_code: null, otp_reveal_required: true }))
    ).toBe(true);
  });

  it('routes a non-OTP approval to the approval modal', () => {
    expect(
      usesOtpModal(prompt({ otp_code: null, otp_reveal_required: false }))
    ).toBe(false);
  });
});
