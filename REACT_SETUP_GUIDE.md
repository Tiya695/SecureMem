# React + TypeScript + Tailwind CSS + shadcn/ui Project Setup Guide

This guide explains how to set up a modern React project supporting **shadcn/ui**, **Tailwind CSS**, and **TypeScript**, and how to integrate the `ShaderBackground` component.

---

## 1. Project Initialization

If you are starting a new project, use the following commands to create a standard Vite React application with TypeScript.

```bash
# Initialize a new React project with Vite & TypeScript
npx -y create-vite@latest securemem-react --template react-ts
cd securemem-react
npm install
```

---

## 2. Install Tailwind CSS

Install Tailwind CSS and its peer dependencies via npm, then generate the config files:

```bash
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

### Configure Tailwind Paths
Update your `tailwind.config.js` to include path configurations for the components and app root:

```javascript
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
```

Add the Tailwind directives to your main CSS file (e.g., `src/index.css`):

```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

---

## 3. Configure TypeScript Path Aliases

To support the `@/components/...` style imports, configure your path mappings in `tsconfig.json` and `tsconfig.app.json`.

Update `tsconfig.json`:
```json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*", "./*"]
    }
  }
}
```

Configure Vite path resolution in `vite.config.ts`:

```typescript
import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./"),
    },
  },
})
```

---

## 4. Initialize shadcn/ui CLI

Initialize the shadcn workspace by running:

```bash
npx shadcn@latest init
```

During initialization, it will prompt you with configuration options. Choose:
* **Style:** Default
* **Base color:** Slate (or your preferred theme)
* **CSS variables:** Yes
* **Location of tailwind.config.js:** `tailwind.config.js`
* **Location of global CSS:** `src/index.css`
* **Import alias for components:** `@/components`
* **Import alias for utils:** `@/lib/utils`

---

## 5. Importance of `/components/ui` Directory

When shadcn/ui is initialized, it determines the default path for reusable UI components. By convention, this default is:
* **Components path:** `/components/ui/` or `src/components/ui/`
* **Styles path:** `src/index.css` or global styles configuration.

### Why is creating `/components/ui/` important?
1. **shadcn CLI Automation:** The shadcn CLI automatically puts components you add (e.g., `npx shadcn@latest add button`) into the `/components/ui/` folder. Creating this directory ensures shadcn works seamlessly out of the box without configurations breaking.
2. **Import Consistency:** Reusable base primitives (like buttons, dialogs, dropdowns) reside in `ui/` to separate them from feature-specific or layout components. The import alias `@/components/ui/` is globally recognized across shadcn projects.
3. **Third-Party Integration:** Standard libraries and components expect your shadcn primitives to be under `components/ui`. Having the folder structures align makes it simple to share and port components between codebases.

---

## 6. How to Run and Verify the Shader Component

Copy the `shader-background.tsx` component into your `/components/ui/` directory:

```bash
# Verify the files match the paths:
/components/ui/shader-background.tsx
/components/demo.tsx
```

In your main app file (e.g. `src/App.tsx`), use the background:

```tsx
import React from 'react';
import { DemoOne } from '@/components/demo';

function App() {
  return (
    <div className="relative min-h-screen text-white">
      {/* Dynamic interactive WebGL shader background */}
      <DemoOne />
      
      {/* Rest of the page contents */}
      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen">
        <h1 className="text-4xl font-extrabold tracking-tight">SecureMem</h1>
        <p className="mt-2 text-lg text-slate-400">Encrypted AI Memory Firewall layer</p>
      </div>
    </div>
  );
}

export default App;
```
