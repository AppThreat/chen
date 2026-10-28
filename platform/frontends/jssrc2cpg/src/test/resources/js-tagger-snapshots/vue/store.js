import { defineStore } from 'pinia';
export const useCart = defineStore('cart', {
  state: () => ({ note: '' }),
  actions: { load() { this.note = location.hash; }, render() { document.write(this.note); } }
});
