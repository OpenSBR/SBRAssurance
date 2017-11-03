using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace SBRAssurance
{
	/// <summary>
	/// Interaction logic for About.xaml
	/// </summary>
	public partial class About : Window
	{
		public static void Show(Window owner)
		{
			About about = new About() { Owner = owner };
			about.ShowDialog();
		}

		public About()
		{
			InitializeComponent();

			ApplicationVersion = typeof(MainWindow).Assembly.GetName().Version.ToString();
			LibraryVersion = typeof(OpenSBR.Xades.XadesSignature).Assembly.GetName().Version.ToString();
			DataContext = this;
		}

		private void Close_Click(object sender, RoutedEventArgs e)
		{
			Close();
		}

		public string ApplicationVersion { get; private set; }
		public string LibraryVersion { get; private set; }
	}
}
