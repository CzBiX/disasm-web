<template>
  <div
    class="flex absolute top-0 right-0
      bg-dark-300 p-2 rounded-lb-2 gap-2
      opacity-20 hover:opacity-80 transition-opacity
      children:(color-neutral-500 transition-color p-3) hover:children:color-neutral-100"
  >
    <slot />
  </div>
</template>
