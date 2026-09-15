<script lang="ts">
  import { onMount } from 'svelte';

  interface Props {
    initial?: number;
  }

  let { initial = 0 }: Props = $props();

  let count = $state(initial);
  let doubled = $derived(count * 2);

  function increment(): void {
    count += 1;
  }

  onMount(() => console.log('mounted', initial));
</script>

<button on:click={increment} disabled={count > 10}>
  {count} ({doubled})
</button>

{#if count > 10}
  <p class="big">That is plenty.</p>
{:else}
  <p>Keep going.</p>
{/if}

<ul>
  {#each [count, doubled] as value, index (index)}
    <li>{index}: {value}</li>
  {/each}
</ul>

<div class="note">{@html `<em>${doubled}</em>`}</div>
