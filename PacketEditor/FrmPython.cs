using System;
using System.IO;
using System.Windows.Forms;

namespace PacketEditor
{
    public partial class FrmPython : Form
    {  
        private readonly string _path;

        public FrmPython(string pathToFile)
        {
            InitializeComponent();

            _path = pathToFile;
            timer1.Start();
        }     

        private void FrmPython_Load(object sender, EventArgs e)
        {
            if (File.Exists(AppDomain.CurrentDomain.BaseDirectory + @"\Scripts\filter.py"))
            {
                txbFilter.Text = File.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + @"\Scripts\filter.py");
            }
        }

        private const int CP_NOCLOSE_BUTTON = 0x200;

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams myCp = base.CreateParams;
                myCp.ClassStyle |= CP_NOCLOSE_BUTTON;
                return myCp;
            }
        }
  

        private void saveFilterToolStripMenuItem_Click(object sender, EventArgs e)
        {
            File.WriteAllText(AppDomain.CurrentDomain.BaseDirectory + "\\Scripts\\filter.py", txbFilter.Text);
        }

        private void txbFilter_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyValue == 190 && txbFilter.Text.IndexOf(".") > 0)
            {
                txbFilter.SelectionStart = txbFilter.Text.IndexOf(".") + 1;
                txbFilter.SelectionLength = 2;
                e.SuppressKeyPress = true;
            }
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            try
            {
                txbOutput.Text = File.ReadAllText(_path);
            }
            catch (Exception ex)
            {
                txbOutput.Text = ex.Message;
            }
        }
    }
}
