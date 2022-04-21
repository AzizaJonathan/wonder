<?php

namespace App\Controller;

use App\Entity\Question;
use App\Form\QuestionType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

#[Route('/question', name: 'question_')]
class QuestionController extends AbstractController
{
  #[Route('/ask', name: 'form')]
  public function index(Request $request, EntityManagerInterface $em): Response
  {

    $question = new Question();
    $formQuestion = $this->createForm(QuestionType::class, $question);

    $formQuestion->handleRequest($request);

    if ($formQuestion->isSubmitted() && $formQuestion->isValid()) {
      $question->setNbrOfResponse(0);
      $question->setRating(0);
      $question->setCreatedAt(new \DateTimeImmutable());
      $em->persist($question);
      $em->flush();
      $this->addFlash('success', 'Votre question a été ajoutée');
      return $this->redirectToRoute('home');
    }

    return $this->render('question/index.html.twig', [
      'form' => $formQuestion->createView(),
    ]);
  }

  #[Route('/{id}', name: 'show')]
  public function show(Request $request, string $id): Response
  {

    $question =   [
      'title' => 'Je suis une super question',
      'content' => 'Lorem ipsum dolor sit amet consectetur adipisicing elit. Tempora, adipisci. Libero aperiam dolores excepturi, quidem maxime accusantium inventore. Illum, odio dolores! Ullam omnis veritatis laborum, animi inventore nostrum optio voluptates.',
      'rating' => 20,
      'author' => [
        'name' => 'Jean Dupont',
        'avatar' => 'https://randomuser.me/api/portraits/men/52.jpg'
      ],
      'nbrOfResponse' => 15
    ];

    return $this->render('question/show.html.twig', [
      'question' => $question,
    ]);
  }
}