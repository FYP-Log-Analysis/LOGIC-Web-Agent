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

export interface TimeRange {
  from: string;
  to: string;
}

interface AuthState {
  user: User | null;
  activeProject: ActiveProject | null;
  projectSelectPending: boolean;
  timeRange: TimeRange | null;

  setUser: (user: User | null) => void;
  setActiveProject: (project: ActiveProject | null) => void;
  setProjectSelectPending: (pending: boolean) => void;
  setTimeRange: (range: TimeRange | null) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  activeProject: null,
  projectSelectPending: false,
  timeRange: null,

  setUser: (user) => set({ user }),
  setActiveProject: (project) => set({ activeProject: project }),
  setProjectSelectPending: (pending) => set({ projectSelectPending: pending }),
  setTimeRange: (range) => set({ timeRange: range }),

  logout: () =>
    set({ user: null, activeProject: null, projectSelectPending: false, timeRange: null }),
}));
