import type { Metadata } from "next";
import "./benchmarks.css";

export const metadata: Metadata = {
  title: "ReverseLens Benchmark Lab",
  description: "Multi-engine reverse-engineering benchmark experiments",
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
