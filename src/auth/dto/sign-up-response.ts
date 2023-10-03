export class SignUpResponse {
  constructor(
    public id: number,
    public email: string,
  ) {}

  public static from(user: any): SignUpResponse {
    return new SignUpResponse(user.id, user.email);
  }
}
