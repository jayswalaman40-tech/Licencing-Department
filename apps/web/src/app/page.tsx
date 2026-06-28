import Link from "next/link";

export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-8 p-8 text-center">
      <div className="space-y-4">
        <h1 className="text-4xl font-bold tracking-tight sm:text-6xl">
          LicenseShield
        </h1>
        <p className="mx-auto max-w-2xl text-lg text-muted-foreground">
          License management for Chrome Extensions. Sell licenses, enforce
          device limits, and validate on every launch — with Razorpay payments
          and offline-capable verification.
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-center gap-4">
        <Link
          href="/signup"
          className="rounded-md bg-primary px-6 py-3 font-medium text-primary-foreground transition hover:opacity-90"
        >
          Get started
        </Link>
        <Link
          href="/login"
          className="rounded-md border border-input px-6 py-3 font-medium transition hover:bg-accent"
        >
          Sign in
        </Link>
      </div>
    </main>
  );
}
