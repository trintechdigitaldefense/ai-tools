---
name: nextjs-dev
description: Next.js App Router development using agent tools — project setup, components, data fetching, deployment
---

# Next.js Development

Build Next.js 14+ App Router apps using bash, write_file, edit_file, and read_file.

## Project Setup

```
bash: npx create-next-app@latest myapp --typescript --tailwind --eslint --app --src-dir --import-alias "@/*" --use-npm
bash: cd myapp && npx shadcn-ui@latest init -y && npx shadcn-ui@latest add button card input
```

## App Router — Routing, Layouts, States

```
bash: mkdir -p src/app/{(auth)/login,(dashboard)/settings,api/users}
```

```
write_file: path=src/app/layout.tsx
import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
const inter = Inter({ subsets: ['latin'] });
export const metadata: Metadata = { title: 'My App' };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body className={inter.className}>{children}</body></html>;
}
```

```
write_file: path=src/app/dashboard/loading.tsx
export default function Loading() { return <div className="animate-pulse p-8">Loading...</div>; }
```

```
write_file: path=src/app/dashboard/error.tsx
'use client';
export default function Error({ error, reset }: { error: Error; reset: () => void }) {
  return <div className="p-8"><h2>Error</h2><button onClick={reset}>Retry</button></div>;
}
```

## Server vs Client Components

Server (default): data fetching, DB access, secrets. Client (`'use client'`): hooks, interactivity, browser APIs.

```
write_file: path=src/app/dashboard/page.tsx
import { Counter } from './counter';
async function getData() {
  const res = await fetch('https://api.example.com/data', { next: { revalidate: 60 } });
  return res.json();
}
export default async function Dashboard() {
  const data = await getData();
  return <div><h1>{data.title}</h1><Counter /></div>;
}
```

```
write_file: path=src/app/dashboard/counter.tsx
'use client';
import { useState } from 'react';
export function Counter() {
  const [n, setN] = useState(0);
  return <button onClick={() => setN(n + 1)}>Count: {n}</button>;
}
```

## Server Actions

```
write_file: path=src/app/actions.ts
'use server';
import { revalidatePath } from 'next/cache';
export async function createItem(formData: FormData) {
  const name = formData.get('name') as string;
  // DB insert
  revalidatePath('/dashboard');
}
```

Use directly in form `action={createItem}` — no client JS needed.

## API Route Handlers

Place `route.ts` in `src/app/api/<name>/`. Export `GET`, `POST`, etc. Use `NextRequest`/`NextResponse`. Supports streaming via `ReadableStream`.

## Middleware — Auth, Redirects, Headers

```
write_file: path=src/middleware.ts
import { NextResponse, type NextRequest } from 'next/server';
export function middleware(req: NextRequest) {
  if (req.nextUrl.pathname.startsWith('/dashboard') && !req.cookies.get('session'))
    return NextResponse.redirect(new URL('/login', req.url));
  return NextResponse.next();
}
export const config = { matcher: ['/dashboard/:path*'] };
```

## Database — Prisma

```
bash: cd myapp && npm install prisma @prisma/client && npx prisma init
```

Define models in `prisma/schema.prisma`, then:
```
bash: npx prisma migrate dev --name init && npx prisma generate
```

Singleton client — prevent hot-reload connection leaks:
```
write_file: path=src/lib/db.ts
import { PrismaClient } from '@prisma/client';
const g = globalThis as unknown as { prisma: PrismaClient };
export const prisma = g.prisma || new PrismaClient();
if (process.env.NODE_ENV !== 'production') g.prisma = prisma;
```

## Environment Variables

Only `NEXT_PUBLIC_*` vars reach the browser. Keep secrets without that prefix.
```
write_file: path=.env.local
DATABASE_URL="postgresql://user:pass@localhost:5432/mydb"
NEXTAUTH_SECRET="use-openssl-rand-base64-32"
NEXT_PUBLIC_APP_URL="http://localhost:3000"
```

## Common Fixes

**Missing "use client"**: `bash: grep -rn "useState\|useEffect\|onClick" src/app --include="*.tsx" -l | xargs grep -L "'use client'"`

**Hydration mismatch**: Use `dynamic(() => import('./C'), { ssr: false })` or wrap in `useEffect`.

**Broken build**: `bash: rm -rf node_modules .next && npm install && npm run build 2>&1 | grep -E "Error|error" | head -20`

## Build & Deploy

```
bash: cd myapp && npm run dev          # development
bash: cd myapp && npm run build        # production build
bash: npm i -g vercel && vercel --prod # deploy to Vercel
```

Standalone for Docker/VMs — add `output: 'standalone'` to next.config.js:
```
bash: cd myapp && npm run build && node .next/standalone/server.js
```
