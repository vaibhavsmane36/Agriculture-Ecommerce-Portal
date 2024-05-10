using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Net;
using System.Net.Mail;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Configuration;
/// <summary>
/// Summary description for utility
/// </summary>
public class utility
{

    static string strCon = ConfigurationManager.ConnectionStrings["conString"].ConnectionString;

	public utility()
	{
		//
		// TODO: Add constructor logic here
		//
	}

    public static string Encrypt(string clearText)
    {
        string EncryptionKey = "MAKV2SPBNI99212";
        byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
        using (Aes encryptor = Aes.Create())
        {
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            encryptor.Key = pdb.GetBytes(32);
            encryptor.IV = pdb.GetBytes(16);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(clearBytes, 0, clearBytes.Length);
                    cs.Close();
                }
                clearText = Convert.ToBase64String(ms.ToArray());
            }
        }
        return clearText;
    }

    
    public static string Decrypt(string cipherText)
    {
        string EncryptionKey = "MAKV2SPBNI99212";
        byte[] cipherBytes = Convert.FromBase64String(cipherText);
        using (Aes encryptor = Aes.Create())
        {
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            encryptor.Key = pdb.GetBytes(32);
            encryptor.IV = pdb.GetBytes(16);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cipherBytes, 0, cipherBytes.Length);
                    cs.Close();
                }
                cipherText = Encoding.Unicode.GetString(ms.ToArray());
            }
        }
        return cipherText;
    }

    //Generate RandomNo
    private static int GenerateOtp()
    {
        int _min = 1000;
        int _max = 9999;
        Random _rdm = new Random();
        return _rdm.Next(_min, _max);
    }

    public static string Registration(string name, string email,string mobilenumber, string acctype,string password)
    {
        string message = "";
        SqlConnection con = new SqlConnection(strCon);
        
        try
        {
            string str= GenerateOtp().ToString();  
            
            SqlCommand cmd = new SqlCommand("uspRegister", con);
            cmd.Connection = con;
            con.Open();
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.AddWithValue("fname", name);
            cmd.Parameters.AddWithValue("email", email);
            cmd.Parameters.AddWithValue("mobile", mobilenumber);
            cmd.Parameters.AddWithValue("password", Encrypt(password));
            cmd.Parameters.AddWithValue("acctype", acctype);
            cmd.Parameters.AddWithValue("otp",str);


            SqlParameter param=new SqlParameter();
            param.ParameterName= "Result";
            param.SqlDbType = SqlDbType.NVarChar;
            param.Size = 20;
            param.Direction= ParameterDirection.Output;
            cmd.Parameters.Add(param);
            cmd.ExecuteNonQuery();
            string retVal = param.Value.ToString();
            if (retVal != "Email Exist" && retVal!="Mobile Exist")
            {
                if (!string.IsNullOrEmpty(retVal))
                {


                   message = "Success,userid:" + retVal;
                   sendMail(email,"OTP for EFarming Registration","Your OTP for registraion in EFarming is "+str+" . The code will be valid for 3 mins only.");
                   

                }
                else
                {
                    message = "Registration Failure";

                }
            }
            else if(retVal=="Email Exist")
            {
                message = "Email Exist";


            }
            else if (retVal == "Mobile Exist")
            {

                message = "Mobile Exist";

            }
            return message;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return message;


        }
        finally { con.Close(); }


    }

    public static string ChkOtp(string mobile, string otp)
    {

        string message = "";
        SqlConnection con = new SqlConnection(strCon);
        try
        {



            SqlCommand cmd = new SqlCommand("uspChkOtp", con);
            cmd.Connection = con;
            con.Open();
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.AddWithValue("mobile", mobile);
            cmd.Parameters.AddWithValue("otp", otp);
            SqlParameter param = new SqlParameter();
            param.ParameterName = "Result";
            param.SqlDbType = SqlDbType.NVarChar;
            param.Size = 20;
            param.Direction = ParameterDirection.Output;
            cmd.Parameters.Add(param);
            cmd.ExecuteNonQuery();
            message = param.Value.ToString();
            return message;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return message;


        }
        finally { con.Close(); }

    }


    public static string resendOtp(string mobile)
    {

        string message = "";
        SqlConnection con = new SqlConnection(strCon);
        try
        {
            
            SqlCommand cmd = new SqlCommand("uspResendOtp", con);
            cmd.Connection = con;
            con.Open();
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.AddWithValue("mobile", mobile);
            cmd.Parameters.AddWithValue("otp",GenerateOtp());
            SqlParameter param = new SqlParameter();
            cmd.ExecuteNonQuery();
            message = "Success";
            return message;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return message;


        }
        finally { con.Close(); }

    }


    public static string login(string email, string password)
    {


        string message = "";
        SqlConnection con = new SqlConnection(strCon);
        try
        {

            SqlCommand cmd = new SqlCommand("usplogin", con);
            DataSet ds = new DataSet();
            SqlDataAdapter da = new SqlDataAdapter();
            cmd.Connection = con;
            con.Open();
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.AddWithValue("email", email);
            cmd.Parameters.AddWithValue("password",Encrypt(password));
            da.SelectCommand = cmd;
            da.Fill(ds);
            if (ds.Tables[0].Rows.Count != 0)
            {
              message = "Success:"+ds.Tables[0].Rows[0][0].ToString()+","+ds.Tables[0].Rows[0][9]+","+ds.Tables[0].Rows[0][1].ToString();
            }
            else
               message = "Fail";
            return message;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return message;


        }
        finally { con.Close(); }

    }

    public static string login1(string email)
    {


        string message = "";
        SqlConnection con = new SqlConnection(strCon);
        try
        {

            SqlCommand cmd = new SqlCommand("usplogin1", con);
            DataSet ds = new DataSet();
            SqlDataAdapter da = new SqlDataAdapter();
            cmd.Connection = con;
            con.Open();
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.AddWithValue("email", email);
            da.SelectCommand = cmd;
            da.Fill(ds);
            if (ds.Tables[0].Rows.Count != 0)
            {
                message = "Success:" + ds.Tables[0].Rows[0][0].ToString() + "," + ds.Tables[0].Rows[0][9] + "," + ds.Tables[0].Rows[0][1].ToString();
            }
            else
                message = "Fail";
            return message;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return message;


        }
        finally { con.Close(); }

    }
    public static string randomPwd()
    {

         // creating a StringBuilder object()
      StringBuilder str_build = new StringBuilder();  
      Random random = new Random();  

      char letter;  

      for (int i = 0; i < 6; i++)
      {
        double flt = random.NextDouble();
        int shift = Convert.ToInt32(Math.Floor(25 * flt));
        letter = Convert.ToChar(shift + 65);
        str_build.Append(letter);  
      }

      return str_build.ToString();
    }
    

    public static string updateProfile(string userid, string name, string email, string mobilenumber, string address,string pincode, string password,string accNo,string bankName,string IFSC)
    {

        string message = "";
        SqlConnection con = new SqlConnection(strCon);
        try
        {
            SqlCommand cmd = new SqlCommand("uspUpdateProfile", con);
            cmd.Connection = con;
            con.Open();
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.AddWithValue("userid", userid);
            cmd.Parameters.AddWithValue("name", name);
            cmd.Parameters.AddWithValue("email", email);
            cmd.Parameters.AddWithValue("mobile", mobilenumber);
            cmd.Parameters.AddWithValue("password", Encrypt(password));
            cmd.Parameters.AddWithValue("address", address);
            cmd.Parameters.AddWithValue("pincode",pincode);
            //cmd.Parameters.AddWithValue("accNo", accNo);
            //cmd.Parameters.AddWithValue("bankName", bankName);
            //cmd.Parameters.AddWithValue("IFSC", IFSC);
            cmd.ExecuteNonQuery();
            message = "Success"; 
            
            return message;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return message;
            
        }
        finally { con.Close(); }

    }

    public static string sendSMS(string mobile, string message)
    {
        string URL = @"https://smshorizon.co.in/api/sendsms.php?user=vinod123101&apikey=yH9yMfZsisXWqjeBczZV&mobile=" + mobile + "&message=" + message ;
      
        HttpWebRequest req = (HttpWebRequest)WebRequest.Create(URL);
        req.Method = "GET";
        req.AllowAutoRedirect = true;

        // allows for validation of SSL conversations
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
        ServicePointManager.Expect100Continue = true;
        ServicePointManager.SecurityProtocol = (SecurityProtocolType)(0xc0 | 0x300 | 0xc00);
                      

        WebResponse respon = req.GetResponse();
        Stream res = respon.GetResponseStream();

        string ret = "";
        byte[] buffer = new byte[1048];
        int read = 0;
        while ((read = res.Read(buffer, 0, buffer.Length)) > 0)
        {
            //Console.Write(Encoding.ASCII.GetString(buffer, 0, read));
            ret += Encoding.ASCII.GetString(buffer, 0, read);
        }
        return ret;
        

    }
    public static string SendPassword(string email)
    {
       
       
        string message = "";
        SqlConnection con = new SqlConnection(strCon);

        try
        {
            SqlCommand cmd = new SqlCommand("uspSendPassword", con);
            cmd.Connection = con;
            con.Open();
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.AddWithValue("email", email);
            SqlParameter param = new SqlParameter();
            param.ParameterName = "Result";
            param.SqlDbType = SqlDbType.NVarChar;
            param.Size = 50;
            param.Direction = ParameterDirection.Output;
            cmd.Parameters.Add(param);
            cmd.ExecuteNonQuery();
            string retVal = param.Value.ToString();
            if (retVal == "No")
            {

                message = retVal;
                return message;
            }
            else
            
            {
                string str =  "Your password is " + Decrypt("vdJd3eYzm0PSb1Kg6/+96XRs2EKbxYz2B7ut3YTsX4Y=");
                sendMail(email,"Password of E-Farming", str);
            }
              return  message = "Sent";
            
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return message;


        }
        finally { con.Close(); }

    }


    public static void sendMail(string ToEmail, string subject, string body)
    {
        try
        {
            MailMessage mm = new MailMessage("vinod.mali05@gmail.com", ToEmail);
            // mm.From = new MailAddress("vinod.mali05@gmail.com");
            mm.Subject = subject;
            mm.Body = body;
            
            mm.IsBodyHtml = true;
            SmtpClient smtp = new SmtpClient();
            smtp.Host = "smtp.gmail.com";
            smtp.EnableSsl = true;
            NetworkCredential NetworkCred = new NetworkCredential();
            NetworkCred.UserName = "vinod.mali05@gmail.com";
            NetworkCred.Password = "Algorithm@1980";
            smtp.UseDefaultCredentials = false;
            smtp.Credentials = NetworkCred;
           // smtp.Port = 587;
        //    smtp.Send(mm);

            SmtpClient objSmtpClient = new SmtpClient();

            objSmtpClient.Host = "smtp.gmail.com";

            objSmtpClient.Port = 587;

            objSmtpClient.Credentials = NetworkCred;

            objSmtpClient.EnableSsl = true;

            objSmtpClient.Send(mm);

           

         }
        catch (Exception ex)
        {
        }

    }


}