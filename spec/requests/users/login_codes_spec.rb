# Test de régression sécurité (PoC — finding F1 : énumération de comptes usagers).
#
# POST /users/login_codes (demande d'un code de connexion usager, formulaire public de
# /users/sign_in, behaviour find_existing_user par défaut) répond DIFFÉREMMENT selon que
# l'email soumis correspond ou non à un compte usager :
#   - compte inexistant  → render "users/sessions/new" en 200 avec le message explicite
#     « Cet email ne correspond à aucun compte usager utilisant la connexion par email »
#     (Users::LoginCodeRequestForm#validate_user_exists) ;
#   - compte existant    → 302 vers new_users_sessions_by_code_path, sans ce message.
# Aucun throttle Rack::Attack ne couvre POST /users/login_codes et aucun captcha n'est
# exigé : un attaquant anonyme peut donc déterminer, à grande échelle, si une adresse
# email arbitraire (un tiers) possède un compte sur la plateforme.
#
# Ce test affirme le comportement SÛR attendu : les deux réponses doivent être
# indiscernables du point de vue d'un attaquant. Il ÉCHOUE tant que l'oracle existe —
# son échec est la preuve de la faille ; il passera lorsqu'une correction uniformisera
# les réponses (message neutre identique dans les deux cas, envoi systématique d'un
# email, etc.).
RSpec.describe "POST /users/login_codes" do
  describe "oracle d'énumération de comptes usagers" do
    it "ne divulgue pas l'existence d'un compte usager : réponses indiscernables pour un email avec et sans compte" do
      create(:user, email: "victime@exemple.fr") # usager standard, sans SSO : loginable par code

      # Un attaquant anonyme soumet deux fois le même formulaire public ; seul l'email varie.
      post users_login_codes_path, params: { login_code_request_form: { email: "inconnu@exemple.fr" } }
      unknown_email_response = response

      post users_login_codes_path, params: { login_code_request_form: { email: "victime@exemple.fr" } }
      existing_email_response = response

      # Signature observable par l'attaquant : statut, redirection, présence du message d'inexistence.
      def oracle_signature(response)
        {
          "statut HTTP" => response.status,
          "redirection" => response.location,
          "message « ne correspond à aucun compte usager » présent" =>
            response.body.include?("ne correspond à aucun compte usager"),
        }
      end

      aggregate_failures "observations brutes (comportement actuel)" do
        expect(unknown_email_response).to have_http_status(:ok)
        expect(unknown_email_response.body).to include("ne correspond à aucun compte usager")
        expect(existing_email_response).to redirect_to(new_users_sessions_by_code_path(email: "victime@exemple.fr"))
        expect(existing_email_response.body).not_to include("ne correspond à aucun compte usager")
      end

      # Propriété de sécurité : les deux signatures DOIVENT être identiques.
      expect(oracle_signature(unknown_email_response))
        .to eq(oracle_signature(existing_email_response)),
             "Les réponses pour inconnu@exemple.fr et victime@exemple.fr sont discernables : " \
             "un attaquant anonyme peut énumérer les comptes usagers via POST /users/login_codes"
    end
  end
end
