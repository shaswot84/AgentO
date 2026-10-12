export interface PaymentIntent {
  id: string;
  amount: number;
  currency: string;
  status: 'pending' | 'succeeded' | 'failed';
  customerId: string;
}

export interface AuthClaims {
  sub: string;
  role: 'customer' | 'operator' | 'admin';
  tenantId: string;
}
