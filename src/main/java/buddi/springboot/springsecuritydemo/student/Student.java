package buddi.springboot.springsecuritydemo.student;

public class Student {

    private final Integer studentId;
    private final String student;

    public Student(Integer studentId, String student) {
        this.studentId = studentId;
        this.student = student;
    }


    public Integer getStudentId() {
        return studentId;
    }

    public String getStudent() {
        return student;
    }

    @Override
    public String toString() {
        return "Student{" +
                "studentId=" + studentId +
                ", student='" + student + '\'' +
                '}';
    }
}
