using System;
using System.Threading;
using System.Windows.Forms;
using SwqlStudio.Utils;

namespace SwqlStudio
{
    internal partial class NewConnection : Form
    {
        private readonly OrionOAuthInfoService _oauthInfoService = new OrionOAuthInfoService();
        private string _authenticatedOAuthUsername = string.Empty;
        private CancellationTokenSource _oauthCts;

        public NewConnection()
        {
            DpiHelper.FixFont(this);
            InitializeComponent();

            cmbServer.Items.AddRange(ConnectionHistory.PreviousServers);
            cmbServer.SelectedIndex = 0;

            cmbServerType.DisplayMember = "Type";
            cmbServerType.Items.AddRange(ConnectionInfo.AvailableServerTypes.ToArray());
            cmbServerType.SelectedIndex = Math.Max(0, ConnectionInfo.AvailableServerTypes.FindIndex(s => s.Type.Equals(ConnectionHistory.PreviousServerType, StringComparison.OrdinalIgnoreCase)));
            cmbUserName.Items.AddRange(ConnectionHistory.PreviousUserNames);
            cmbUserName.SelectedIndex = 0;

            CheckIfUserCredentialsNecessary();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _oauthCts?.Cancel();
            base.OnFormClosing(e);
        }

        public ConnectionInfo ConnectionInfo
        {
            get
            {
                if (IsOAuthSelected)
                    return new ConnectionInfo(cmbServer.Text, _authenticatedOAuthUsername, _oauthInfoService);

                return new ConnectionInfo(cmbServer.Text, cmbUserName.Text, tePassword.Text, cmbServerType.Text);
            }
        }

        private bool IsOAuthSelected =>
            (cmbServerType.SelectedItem as ServerType)?.Type.Equals("Orion (v3) OAuth", StringComparison.OrdinalIgnoreCase) == true;

        private async void connectButton_Click(object sender, EventArgs e)
        {
            if (!IsOAuthSelected)
            {
                SaveHistory();
                DialogResult = DialogResult.OK;
                return;
            }

            connectButton.Enabled = false;
            _oauthCts = new CancellationTokenSource();

            _oauthInfoService.InitTokenManager(cmbServer.Text);

            try
            {
                await _oauthInfoService.TokenManager.AcquireTokenAsync(_oauthCts.Token);
                _authenticatedOAuthUsername = _oauthInfoService.TokenManager.LastAccountUsername ?? string.Empty;
                SaveHistory();
                DialogResult = DialogResult.OK;
            }
            catch (OperationCanceledException)
            {
                // user hit Cancel — dialog closes normally, nothing to report
            }
            catch (Exception ex)
            {
                MessageBox.Show("Authentication failed: " + ex.Message, "OAuth Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                _oauthCts?.Dispose();
                _oauthCts = null;
                if (!IsDisposed)
                    connectButton.Enabled = true;
            }
        }

        private void SaveHistory()
        {
            ConnectionHistory.AddServer(cmbServer.Text);
            ConnectionHistory.AddUser(cmbUserName.Text);
            ConnectionHistory.PreviousServerType = (cmbServerType.SelectedItem as ServerType).Type;
        }

        private void cmbServerType_SelectedIndexChanged(object sender, EventArgs e)
        {
            CheckIfUserCredentialsNecessary();
        }

        private void CheckIfUserCredentialsNecessary()
        {
            bool isOAuth = IsOAuthSelected;
            bool requiresAuthentication = !isOAuth && (cmbServerType.SelectedItem as ServerType).IsAuthenticationRequired;

            label3.Visible = !isOAuth;
            label4.Visible = !isOAuth;
            cmbUserName.Visible = !isOAuth;
            tePassword.Visible = !isOAuth;

            cmbUserName.Enabled = requiresAuthentication;
            tePassword.Enabled = requiresAuthentication;

            if (!isOAuth && !requiresAuthentication)
            {
                cmbUserName.Text = string.Empty;
                tePassword.Text = string.Empty;
            }
            else if (!isOAuth && requiresAuthentication)
            {
                if (ConnectionHistory.PreviousUserNames.Length > 0)
                    cmbUserName.Text = ConnectionHistory.PreviousUserNames[0];
            }
        }
    }
}
