import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://skxzfkudduqrubtgtodp.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNreHpma3VkZHVxcnVidGd0b2RwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDU1ODAwNzMsImV4cCI6MjA2MTE1NjA3M30.Wj3V5-swysAz8xAbA4lKmo-NNu_mv1UW_X4BgFNq0ag'; // From Supabase Settings → API

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
