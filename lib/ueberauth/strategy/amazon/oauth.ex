defmodule Ueberauth.Strategy.Amazon.OAuth do
  @moduledoc """
  OAuth2 for Amazon.
  Add `client_id` and `client_secret` to your configuration:
  config :ueberauth, Ueberauth.Strategy.Amazon.OAuth,
    client_id: System.get_env("AMAZON_APP_ID"),
    client_secret: System.get_env("AMAZON_APP_SECRET")
  """
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "https://amazon.com/",
    authorize_url: "https://www.amazon.com/ap/oa",
    token_url: "https://api.amazon.com/auth/o2/token",
    #token_method: :get
  ]

  @doc """
  Construct a client for requests to Amazon.
  This will be setup automatically for you in `Ueberauth.Strategy.Amazon`.
  These options are only useful for usage outside the normal callback phase
  of Ueberauth.
  """
  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Amazon.OAuth, [])

    opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    json_library = Ueberauth.json_library()

    OAuth2.Client.new(opts)
    |> OAuth2.Client.put_serializer("application/json", json_library)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth.
  No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get_token!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.get_token!(params)
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param(:client_secret, client.client_secret)
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end
end
