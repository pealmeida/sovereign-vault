<script lang="ts">
  import type { Mode } from '../lib/types';
  import { modeClass } from '../lib/formatters';
  let { mode }: { mode: Mode } = $props();
</script>

<span class="mode-pill {modeClass(mode)}">{mode}</span>
