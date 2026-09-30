import { render, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ApprovalPrompt } from '../lib/types';
import OtpModal from './OtpModal.svelte';

/// Tests for the OTP modal's reveal gate (ADR-0025 §7.3).
///
/// # The bug these guard
///
/// The OTP code used to arrive in the approval event itself, so a process
/// that can read the screen could read the code and resend the request -
/// the exact cross-channel check the OTP mode exists for, defeated by
/// synthetic input. On a protected system the event now carries no code:
/// it appears only after `approval_reveal_otp` passes an OS presence
/// verification bound to that request.

const invokeMock = vi.fn();

vi.mock('../lib/tauri', () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => invokeMock(cmd, args),
}));

const toastErrors: unknown[] = [];
vi.mock('../stores/toast.svelte', () => ({
  toastStore: {
    setError: (e: unknown) => {
      toastErrors.push(e);
    },
    setNotice: () => {},
    get notice() {
      return '';
    },
    get error() {
      return '';
    },
  },
}));

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
    otp_reveal_required: true,
    pre_unlock: false,
    ...overrides,
  };
}

function getByTextNot(query: string): boolean {
  return document.body.textContent?.includes(query) ?? false;
}

describe('OtpModal', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    toastErrors.length = 0;
  });

  it('renders no code text for a protected prompt', () => {
    render(OtpModal, { props: { prompt: prompt(), onClose: () => {} } });
    expect(invokeMock).not.toHaveBeenCalled();
    expect(getByTextNot('123456')).toBe(false);
  });

  it('reveals the code through the backend command after clicking Reveal', async () => {
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'approval_reveal_otp') return Promise.resolve('123456');
      return Promise.resolve(null);
    });

    const { getByText } = render(OtpModal, {
      props: { prompt: prompt(), onClose: () => {} },
    });
    getByText(/Reveal code/).click();

    await waitFor(() => expect(getByTextNot('123456')).toBe(true));
    expect(invokeMock).toHaveBeenCalledWith('approval_reveal_otp', { id: 7 });
  });

  it('shows the code directly on a declared system', () => {
    render(OtpModal, {
      props: {
        prompt: prompt({ otp_code: '654321', protected: false, otp_reveal_required: false }),
        onClose: () => {},
      },
    });
    expect(getByTextNot('654321')).toBe(true);
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it('names the request the code belongs to', () => {
    render(OtpModal, { props: { prompt: prompt(), onClose: () => {} } });
    expect(getByTextNot('ReadFile')).toBe(true);
    expect(getByTextNot('notes')).toBe(true);
    expect(getByTextNot('a.txt')).toBe(true);
  });

  it('offers no copy button while the code is still hidden', () => {
    const { queryByRole } = render(OtpModal, {
      props: { prompt: prompt(), onClose: () => {} },
    });
    expect(queryByRole('button', { name: 'Copy code' })).toBeNull();
  });

  it('copies the visible code to the clipboard when the copy button is clicked', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });

    const { getByRole } = render(OtpModal, {
      props: {
        prompt: prompt({ otp_code: '654321', protected: false, otp_reveal_required: false }),
        onClose: () => {},
      },
    });
    getByRole('button', { name: 'Copy code' }).click();

    await waitFor(() => expect(writeText).toHaveBeenCalledWith('654321'));
  });
});
