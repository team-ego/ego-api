module Users
  class OmniauthCallbacksController < DeviseTokenAuth::OmniauthCallbacksController
    include Devise::Controllers::Rememberable

    def redirect_callbacks

      # derive target redirect route from 'resource_class' param, which was set
      # before authentication.
      devise_mapping = [request.env['omniauth.params']['namespace_name'],
                        request.env['omniauth.params']['resource_class'].underscore.gsub('/', '_')].compact.join('_')
      path = "#{Devise.mappings[devise_mapping.to_sym].fullpath}/#{params[:provider]}/callback"
      klass = request.scheme == 'https' ? URI::HTTPS : URI::HTTP
      redirect_route = klass.build(host: request.host, port: request.port, path: path).to_s

      # preserve omniauth info for success route. ignore 'extra' in twitter
      # auth response to avoid CookieOverflow.

      session['dta.omniauth.auth'] = request.env['omniauth.auth'].except('extra')
      # session['dta.omniauth.extra'] = request.env['omniauth.auth.extra']
      session['dta.omniauth.params'] = request.env['omniauth.params']

      redirect_to redirect_route
    end

    def omniauth_success
      get_resource_from_auth_hash
      # create_token_info
      set_token_on_resource
      create_auth_params

      # ここは使わないのでコメントアウト
      #if resource_class.devise_modules.include?(:confirmable)
      #  # don't send confirmation email!!!
      #  @resource.skip_confirmation!
      #end

      sign_in(:user, @resource, store: false, bypass: false)

      # 動作確認用にユーザ情報を保存できたらjsonをそのまま返す処理
      # if @resource.save!
      #   # update_token_authをつけることでレスポンスヘッダーに認証情報を付与できる。
      #   update_auth_header
      #   yield @resource if block_given?
      #   render json: @resource, status: :ok
      # else
      #   render json: { message: "failed to login" }, status: 500
      # end

      # 本実装時はこちらを使用する
      @resource.save!

      # update_auth_header # これは自分で追加する
      yield @resource if block_given?

      render_data_or_redirect('deliverCredentials', @auth_params.as_json, @resource.as_json)

    end

    protected
      def assign_provider_attrs(user, auth_hash)
        user = User.where(provider: auth_hash['provider'], uid: auth_hash['uid']).first do |user|
          user.provider = auth_hash['provider']
          user.uid      = auth_hash['uid']
          user.name     = auth_hash['info']['name']
          user.nickname     = auth_hash['info']['nickname']
          user.image     = auth_hash['info']['image']
        end
        # attrs = auth_hash['info'].slice(*user.attributes.keys)
        # user.assign_attributes(attrs)
      end

      def get_resource_from_auth_hash
        # find or create user by provider and provider uid

        @resource = resource_class.where({
          uid:      auth_hash['uid'],
          provider: auth_hash['provider']
        }).first_or_initialize

        if @resource.new_record?
          @oauth_registration = true
          # これが呼ばれるとエラーになるのでコメントアウトする
          #set_random_password
        end

        # sync user info with provider, update/generate auth token
        assign_provider_attrs(@resource, auth_hash)

        # assign any additional (whitelisted) attributes
        extra_params = whitelisted_params
        @resource.assign_attributes(extra_params) if extra_params

        @resource
      end
  end
end
