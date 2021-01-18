defmodule Ueberauth.Strategy.Amazon do
  @moduledoc """
  Ueberauth strategy for Login with Amazon
  """
  use Ueberauth.Strategy, uid_field: :user_id, default_scope: :profile

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Auth.Credentials

  def client do

  end

  @doc """
  Handles initial request for Login with Amazon
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    opts = [redirect_uri: callback_url(conn), scope: scopes]
    opts =
      if conn.params["state"], do: Keyword.put(opts, :state, conn.params["state"]), else: opts
    authorize_url = Ueberauth.Strategy.Amazon.OAuth.authorize_url!(opts)
    redirect!(conn, authorize_url)
  end

  @doc """
  Handles callback from Login with Amazon
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = oauth_client_options_from_conn(conn)
    try do
      client = Ueberauth.Strategy.Amazon.OAuth.get_token!([code: code], opts)
      fetch_user(conn, client)
    rescue
      OAuth2.Error ->
        set_errors!(conn, [error("invalid_code", "The code has been used or has expired")])
    end
  end

    @doc false
    def handle_cleanup!(conn) do
      conn
      |> put_private(:amazon_user, nil)
      |> put_private(:amazon_token, nil)
    end


  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.amazon_user[uid_field]
  end

  def credentials(conn) do
    token = conn.private.amazon_token
    scopes = token.other_params["scope"] || ""
    scopes = String.split(scopes, ",")

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: scopes,
      token: token.access_token,
      refresh_token: token.refresh_token
    }
  end

  def info(conn) do
    user = conn.private.amazon_user

    %Info{
      name: user["name"],
      email: user["email"]
    }
  end

  defp fetch_user(conn, client) do
    conn = put_private(conn, :amazon_token, client.token)
    case OAuth2.Client.get(client, "https://api.amazon.com/user/profile") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: user}}
      when status_code in 200..399 ->
        put_private(conn, :amazon_user, user)

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  defp oauth_client_options_from_conn(conn) do
    base_options = [redirect_uri: callback_url(conn)]
    request_options = conn.private[:ueberauth_request_options].options

    case {request_options[:client_id], request_options[:client_secret]} do
      {nil, _} -> base_options
      {_, nil} -> base_options
      {id, secret} -> [client_id: id, client_secret: secret] ++ base_options
    end
  end
end
