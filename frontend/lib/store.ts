import { create } from "zustand";

export interface User {
  username: string;
  role: "admin" | "analyst" | "user";
  userId: number;
  email: string;
}

export interface ActiveProject {
  id: string;
  name: string;
}

interface AuthState {
  user: User | null;
  activeProject: ActiveProject | null;
  projectSelectPending: boolean;

  setUser: (user: User | null) => void;
  setActiveProject: (project: ActiveProject | null) => void;
  setProjectSelectPending: (pending: boolean) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  activeProject: null,
  projectSelectPending: false,

  setUser: (user) => set({ user }),
  setActiveProject: (project) => set({ activeProject: project }),
  setProjectSelectPending: (pending) => set({ projectSelectPending: pending }),

  logout: () =>
    set({ user: null, activeProject: null, projectSelectPending: false }),
}));
