let notice = $state('');
let errorMsg = $state('');
let noticeTimer: ReturnType<typeof setTimeout> | null = null;
let errorTimer: ReturnType<typeof setTimeout> | null = null;

export const toastStore = {
  get notice() { return notice; },
  get error() { return errorMsg; },

  setNotice(msg: string, duration = 4000) {
    notice = msg;
    if (noticeTimer) clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => { notice = ''; }, duration);
  },

  setError(e: unknown, duration = 6000) {
    errorMsg = e instanceof Error ? e.message : String(e);
    if (errorTimer) clearTimeout(errorTimer);
    errorTimer = setTimeout(() => { errorMsg = ''; }, duration);
  },
};
