const API_BASE = '/api';

const API = {
  async request(endpoint, options = {}) {
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {})
        }
      });
      if (!res.ok) {
        let errMsg = res.statusText;
        try {
          const errData = await res.json();
          errMsg = errData.message || errData.error || errMsg;
        } catch (e) {
          const textData = await res.text();
          errMsg = textData || errMsg;
        }
        throw new Error(errMsg);
      }
      return await res.json();
    } catch (err) {
      console.error(`API Error on ${endpoint}:`, err);
      throw err;
    }
  },

  async getServers(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/servers${query ? '?' + query : ''}`);
  },

  async getServer(slug) {
    return this.request(`/servers/${slug}`);
  },

  async getServerTools(slug) {
    return this.request(`/servers/${slug}/tools`);
  },

  async getServerVersions(slug) {
    return this.request(`/servers/${slug}/versions`);
  },

  async publishServer(data) {
    return this.request('/servers', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async updateServer(slug, data) {
    return this.request(`/servers/${slug}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  },

  async deleteServer(slug) {
    return this.request(`/servers/${slug}`, {
      method: 'DELETE'
    });
  },

  async installServer(slug, clientType) {
    return this.request(`/servers/${slug}/install`, {
      method: 'POST',
      body: JSON.stringify({ clientType })
    });
  },

  async getCategories() {
    return this.request('/categories');
  },

  async getCategory(slug) {
    return this.request(`/categories/${slug}`);
  },

  async getTags() {
    return this.request('/tags');
  },

  async getClients() {
    return this.request('/clients');
  },

  async search(query) {
    return this.request(`/search?q=${encodeURIComponent(query)}`);
  },

  async getStats() {
    return this.request('/stats');
  },

  async register(data) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async login(data) {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async logout() {
    return this.request('/auth/logout', { method: 'POST' });
  },

  async getCurrentUser() {
    try {
      return await this.request('/auth/me');
    } catch (e) {
      return null;
    }
  },

  async getUser(username) {
    return this.request(`/users/${username}`);
  }
};

window.API = API;
