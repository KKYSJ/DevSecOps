const API_BASE = '/api/v1';

export async function fetchJson<T>(path: string): Promise<T> {
  try {
    const res = await fetch(`${API_BASE}${path}`);
    if (!res.ok) {
      console.error(`API error: ${path} → ${res.status}`);
      throw new Error(`API ${res.status}`);
    }
    const data = await res.json();
    console.log(`API ok: ${path}`, Object.keys(data));
    return data;
  } catch (e) {
    console.error(`fetchJson failed: ${path}`, e);
    throw e;
  }
}
