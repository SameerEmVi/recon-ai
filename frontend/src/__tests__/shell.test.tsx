import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { TokenGate } from "@/components/TokenGate";
import { apiFetch } from "@/lib/api";
import { setToken } from "@/lib/auth";

beforeEach(() => localStorage.clear());

describe("TokenGate", () => {
  it("shows the unlock prompt when no token is stored", () => {
    render(
      <TokenGate>
        <div>protected-content</div>
      </TokenGate>
    );
    expect(screen.getByText(/access token/i)).toBeInTheDocument();
    expect(screen.queryByText("protected-content")).not.toBeInTheDocument();
  });

  it("renders children once a token is present", () => {
    setToken("abc123");
    render(
      <TokenGate>
        <div>protected-content</div>
      </TokenGate>
    );
    expect(screen.getByText("protected-content")).toBeInTheDocument();
  });
});

describe("apiFetch", () => {
  afterEach(() => vi.restoreAllMocks());

  it("injects the bearer token and parses JSON", async () => {
    setToken("tok-xyz");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const data = await apiFetch<{ status: string }>("/api/health");
    expect(data.status).toBe("ok");
    const headers = fetchMock.mock.calls[0][1].headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer tok-xyz");
  });

  it("throws ApiError with the server detail on non-2xx", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "nope" }), { status: 401 })
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(apiFetch("/api/scans")).rejects.toMatchObject({ status: 401, message: "nope" });
  });
});
