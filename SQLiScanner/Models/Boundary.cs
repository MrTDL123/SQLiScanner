using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Models
{
    // Boundary - Cấu trúc {prefix}{sufix}
    public class Boundary
    {
        // Đại diện độ phức tạp của context
        public int Level { get; set; }

        // Đại diện mệnh đề hiện tại của boundary đang áp dụng
        // 0=Always, 1=WHERE/HAVING, 2=GROUP BY, 3=ORDER BY, 4=LIMIT,
        // 5=OFFSET, 6=TOP, 7=Table name, 8=Column name, 9=Pre-WHERE
        public string Clause { get; set; }

        // Nơi chèn Payload
        // 1.Nối thêm đằng sau giá trị ban đầu
        // 2.Thay giá trị ban đầu thành một số âm ngẫu nhiên + payload
        // 3.Thay thế hoàn toàn giá trị ban đầu với payload
        public string Where { get; set; }

        // Giá trị tham số hiện tại
        // 1. Integer 
        // 2. Giá trị string nằm trong ngoặc đơn '
        // 3. Giá trị string nằm trong ngoặc đơn và sau mệnh đề LIKE (VD: WHERE title LIKE '%[INPUT]%')
        // 4. Giá trị string nằm trong ngoặc đôi
        // 5. Giá trị string nằm trong ngoặc đôi và sau mệnh đề LIKE (VD: WHERE title LIKE "%[INPUT]%")
        // 6. Identifier (Giá trị dựa vào tên cột) -> Cực hiếm
        public int PType { get; set; }

        // Chuỗi chèn ở phía trước Payload
        public string Prefix { get; set; }

        // Chuỗi chèn ở phía sau payload
        public string Suffix { get; set; }
        public string Comment { get; set; } 

        // Tên context
        // "INTEGER", "STRING_SINGLE_QUOTE", "LIKE_SINGLE_QUOTE", 
        // "NESTED_PARENTHESIS"
        public string ContextName { get; set; }

        public override string ToString()
        {
            return $"[{ContextName}] Level:{Level} PType:{PType} Prefix='{Prefix}' Suffix='{Suffix}'";
        }
    }
}
