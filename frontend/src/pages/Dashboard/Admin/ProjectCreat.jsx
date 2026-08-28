import {
  useState,
} from "react";

import "./ProjectCreat.css";


function ProjectCreate({
  onCancel,
}) {

  /*
   * ========================================
   * 프로젝트 기본 입력 데이터
   * ========================================
   */
  const [
    formData,
    setFormData,
  ] = useState({

    name: "",

    description: "",

    language: "Java",

    sourceType: "upload",

    repositoryUrl: "",

    internalPath: "",

  });


  /*
   * 파일 업로드 방식에서 사용할 파일
   *
   * File 객체이기 때문에
   * 일반 문자열 formData와 따로 관리
   */
  const [
    sourceFile,
    setSourceFile,
  ] = useState(null);


  /*
   * 사용자에게 보여줄 오류 메시지
   */
  const [
    error,
    setError,
  ] = useState("");


  /*
   * ========================================
   * 일반 input / textarea / select 변경
   * ========================================
   */
  const handleChange = (
    e
  ) => {

    const {
      name,
      value,
    } = e.target;


    setFormData(
      (prev) => ({

        ...prev,

        [name]:
          value,

      })
    );
  };


  /*
   * ========================================
   * 파일 선택
   * ========================================
   */
  const handleFileChange = (
    e
  ) => {

    const file =
      e.target.files[0];


    if (!file) {
      setSourceFile(null);

      return;
    }


    setSourceFile(
      file
    );
  };


  /*
   * ========================================
   * 프로젝트 등록
   * ========================================
   *
   * 현재는 프론트 화면 구현 단계이므로
   * 실제 서버 요청은 보내지 않는다.
   *
   * 이후 Django API와 연결할 예정
   */
  const handleSubmit = (
    e
  ) => {

    /*
     * form의 기본 새로고침 방지
     */
    e.preventDefault();


    /*
     * 이전 오류 메시지 제거
     */
    setError("");


    /*
     * 프로젝트 이름 검사
     */
    if (
      !formData.name.trim()
    ) {

      setError(
        "프로젝트 이름을 입력해주세요."
      );

      return;
    }


    /*
     * 파일 업로드 방식 검사
     */
    if (
      formData.sourceType === "upload" &&
      !sourceFile
    ) {

      setError(
        "분석할 소스 파일을 선택해주세요."
      );

      return;
    }


    /*
     * Repository 방식 검사
     */
    if (
      formData.sourceType === "repository" &&
      !formData.repositoryUrl.trim()
    ) {

      setError(
        "Repository URL을 입력해주세요."
      );

      return;
    }


    /*
     * 내부 경로 방식 검사
     */
    if (
      formData.sourceType === "internal" &&
      !formData.internalPath.trim()
    ) {

      setError(
        "내부 소스 경로를 입력해주세요."
      );

      return;
    }


    /*
     * 현재는 테스트용
     *
     * 나중에는 여기에서
     * Django API를 호출한다.
     */
    console.log(
      "프로젝트 기본 정보:",
      formData
    );


    console.log(
      "업로드 파일:",
      sourceFile
    );
  };


  return (
    <div className="project-create">


      {/* =================================
          페이지 상단
      ================================= */}

      <div className="project-create-header">


        <button
          type="button"

          className="back-button"

          onClick={
            onCancel
          }
        >
          ← 목록으로
        </button>


        <div className="project-create-title">

          <h1>
            프로젝트 등록
          </h1>


          <p>
            정적 보안 분석을 수행할
            프로젝트 정보를 입력합니다.
          </p>

        </div>


      </div>



      {/* =================================
          프로젝트 등록 Form
      ================================= */}

      <form
        className="project-create-form"

        onSubmit={
          handleSubmit
        }
      >


        {/* =================================
            프로젝트 이름
        ================================= */}

        <div className="form-group">

          <label
            htmlFor="name"
          >
            프로젝트 이름

            <span className="required">
              *
            </span>
          </label>


          <input
            id="name"

            name="name"

            type="text"

            value={
              formData.name
            }

            onChange={
              handleChange
            }

            placeholder=
              "프로젝트 이름을 입력하세요."
          />

        </div>



        {/* =================================
            프로젝트 설명
        ================================= */}

        <div className="form-group">

          <label
            htmlFor="description"
          >
            프로젝트 설명
          </label>


          <textarea
            id="description"

            name="description"

            value={
              formData.description
            }

            onChange={
              handleChange
            }

            rows="5"

            placeholder=
              "프로젝트에 대한 설명을 입력하세요."
          />

        </div>



        {/* =================================
            분석 언어
        ================================= */}

        <div className="form-group">

          <label
            htmlFor="language"
          >
            분석 언어

            <span className="required">
              *
            </span>
          </label>


          <select
            id="language"

            name="language"

            value={
              formData.language
            }

            onChange={
              handleChange
            }
          >

            <option value="Java">
              Java
            </option>


            <option value="JavaScript">
              JavaScript
            </option>


            <option value="Python">
              Python
            </option>

          </select>

        </div>



        {/* =================================
            소스 유형
        ================================= */}

        <div className="form-group">

          <label
            htmlFor="sourceType"
          >
            소스 유형

            <span className="required">
              *
            </span>
          </label>


          <select
            id="sourceType"

            name="sourceType"

            value={
              formData.sourceType
            }

            onChange={
              handleChange
            }
          >

            <option value="upload">
              파일 업로드
            </option>


            <option value="repository">
              저장소 연계
            </option>


            <option value="internal">
              내부 경로
            </option>

          </select>

        </div>



        {/* =================================
            파일 업로드
        ================================= */}

        {
          formData.sourceType === "upload" && (

            <div className="form-group">

              <label
                htmlFor="sourceFile"
              >
                소스 파일

                <span className="required">
                  *
                </span>
              </label>


              <input
                id="sourceFile"

                type="file"

                onChange={
                  handleFileChange
                }
              />


              {
                sourceFile && (

                  <p className="selected-file">

                    선택된 파일: {
                      sourceFile.name
                    }

                  </p>

                )
              }

            </div>

          )
        }



        {/* =================================
            Repository 연계
        ================================= */}

        {
          formData.sourceType ===
            "repository" && (

            <div className="form-group">

              <label
                htmlFor="repositoryUrl"
              >
                Repository URL

                <span className="required">
                  *
                </span>
              </label>


              <input
                id="repositoryUrl"

                name="repositoryUrl"

                type="text"

                value={
                  formData.repositoryUrl
                }

                onChange={
                  handleChange
                }

                placeholder=
                  "Repository URL을 입력하세요."
              />

            </div>

          )
        }



        {/* =================================
            내부 경로
        ================================= */}

        {
          formData.sourceType ===
            "internal" && (

            <div className="form-group">

              <label
                htmlFor="internalPath"
              >
                내부 소스 경로

                <span className="required">
                  *
                </span>
              </label>


              <input
                id="internalPath"

                name="internalPath"

                type="text"

                value={
                  formData.internalPath
                }

                onChange={
                  handleChange
                }

                placeholder=
                  "/source/project"
              />

            </div>

          )
        }



        {/* =================================
            오류 메시지
        ================================= */}

        {
          error && (

            <p className="project-create-error">
              {error}
            </p>

          )
        }



        {/* =================================
            하단 버튼
        ================================= */}

        <div className="project-create-actions">


          <button
            type="button"

            className="cancel-button"

            onClick={
              onCancel
            }
          >
            취소
          </button>


          <button
            type="submit"

            className="submit-button"
          >
            프로젝트 등록
          </button>


        </div>


      </form>


    </div>
  );
}


export default ProjectCreate;