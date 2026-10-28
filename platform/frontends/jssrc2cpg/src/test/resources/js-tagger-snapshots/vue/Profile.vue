<script setup>
import { computed, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
const route = useRoute();
const id = computed(() => route.params.id);
const html = ref('');
watch(id, (value) => { html.value = value; });
function show() { document.body.innerHTML = html.value + id.value; }
</script>
<template><button @click="show">{{ id }}</button></template>
